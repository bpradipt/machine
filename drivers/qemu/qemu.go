package qemu

import (
	"archive/tar"

	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/codegangsta/cli"
	//	"github.com/docker/docker/api"
	"github.com/docker/machine/drivers"
	"github.com/docker/machine/provider"
	"github.com/docker/machine/state"

	"github.com/docker/machine/ssh"
	"github.com/docker/machine/utils"

	log "github.com/Sirupsen/logrus"
)

// Driver is the driver used when no driver is selected. It is used to
// connect to existing Docker hosts by specifying the URL of the host as
// an option.
type Driver struct {
	URL            string
	MachineName    string
	SSHUser        string
	SSHPort        int
	Memory         int
	DiskSize       int
	Boot2DockerURL string
	NetworkBridge  string
	CaCertPath     string
	PrivateKeyPath string
	SwarmMaster    bool
	SwarmHost      string
	SwarmDiscovery string
	storePath      string
}

func init() {
	drivers.Register("qemu", &drivers.RegisteredDriver{
		New:            NewDriver,
		GetCreateFlags: GetCreateFlags,
	})
}

func GetCreateFlags() []cli.Flag {
	return []cli.Flag{
		cli.IntFlag{
			Name:  "qemu-memory",
			Usage: "Size of memory for host in MB",
			Value: 1024,
		},
		cli.IntFlag{
			Name:  "qemu-disk-size",
			Usage: "Size of disk for host in MB",
			Value: 20000,
		},
		cli.StringFlag{
			EnvVar: "QEMU_BOOT2DOCKER_URL",
			Name:   "qemu-boot2docker-url",
			Usage:  "The URL of the boot2docker image. Defaults to the latest available version",
			Value:  "",
		},
		cli.StringFlag{
			Name:  "qemu-network-bridge",
			Usage: "Name of bridge to be used for networking",
			Value: "virbr0",
		},
	}
}

func NewDriver(machineName string, storePath string, caCert string, privateKey string) (drivers.Driver, error) {
	return &Driver{MachineName: machineName, storePath: storePath, CaCertPath: caCert, PrivateKeyPath: privateKey, Memory: 2048, SSHPort: 2222, SSHUser: "docker"}, nil
}

func (d *Driver) AuthorizePort(ports []*drivers.Port) error {
	return nil
}

func (d *Driver) DeauthorizePort(ports []*drivers.Port) error {
	return nil
}

func (d *Driver) GetMachineName() string {
	return d.MachineName
}

func (d *Driver) GetSSHHostname() (string, error) {
	return "localhost", nil
}

func (d *Driver) GetSSHKeyPath() string {
	return filepath.Join(d.storePath, "id_rsa")
}

func (d *Driver) GetSSHPort() (int, error) {
	return d.SSHPort, nil
}

func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = "docker"
	}

	return d.SSHUser
}

func (d *Driver) GetProviderType() provider.ProviderType {
	return provider.Local
}

func (d *Driver) DriverName() string {
	return "qemu"
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.Memory = flags.Int("qemu-memory")
	d.DiskSize = flags.Int("qemu-disk-size")
	d.Boot2DockerURL = flags.String("qemu-boot2docker-url")
	d.NetworkBridge = flags.String("qemu-network-bridge")
	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmHost = flags.String("swarm-host")
	d.SwarmDiscovery = flags.String("swarm-discovery")

	return nil
}

func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}
	return fmt.Sprintf("tcp://%s:2376", ip), nil
}

func (d *Driver) GetIP() (string, error) {
	// DHCP is used to get the IP, so qemu hosts don't have IPs unless
	// they are running
	s, err := d.GetState()
	if err != nil {
		return "", err
	}
	if s != state.Running {
		return "", drivers.ErrHostIsNotRunning
	}
	cmd, err := drivers.GetSSHCommandFromDriver(d, "ip addr show dev eth1")
	if err != nil {
		return "", err
	}

	// reset to nil as if using from Host Stdout is already set when using DEBUG
	cmd.Stdout = nil

	b, err := cmd.Output()
	if err != nil {
		return "", err
	}
	out := string(b)
	log.Debugf("SSH returned: %s\nEND SSH\n", out)
	// parse to find: inet 192.168.59.103/24 brd 192.168.59.255 scope global eth1
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		vals := strings.Split(strings.TrimSpace(line), " ")
		if len(vals) >= 2 && vals[0] == "inet" {
			return vals[1][:strings.Index(vals[1], "/")], nil
		}
	}

	return "", fmt.Errorf("No IP address found %s", out)
	return "", nil
}

func (d *Driver) GetState() (state.State, error) {

	ret, err := d.RunQMPCommand("query-status")
	if err != nil {
       		return state.Error, err
	}
	// RunState is one of:
	// 'debug', 'inmigrate', 'internal-error', 'io-error', 'paused',
	// 'postmigrate', 'prelaunch', 'finish-migrate', 'restore-vm',
	// 'running', 'save-vm', 'shutdown', 'suspended', 'watchdog',
	// 'guest-panicked'
	switch ret["status"] {
	case "running":
		return state.Running, nil
	case "paused":
		return state.Paused, nil
	case "shutdown":
		return state.Stopped, nil
	}
	return state.None, nil
}

func (d *Driver) PreCreateCheck() error {
	return nil
}

func (d *Driver) Create() error {
	var (
		err    error
		isoURL string
	)
	d.SSHPort, err = getAvailableTCPPort()
	if err != nil {
		return err
	}
	b2dutils := utils.NewB2dUtils("", "")
	imgPath := utils.GetMachineCacheDir()
	isoFilename := "boot2docker.iso"
	commonIsoPath := filepath.Join(imgPath, "boot2docker.iso")
	// just in case boot2docker.iso has been manually deleted
	if _, err := os.Stat(imgPath); os.IsNotExist(err) {
		if err := os.Mkdir(imgPath, 0700); err != nil {
			return err
		}

	}

	if d.Boot2DockerURL != "" {
		isoURL = d.Boot2DockerURL
		log.Infof("Downloading %s from %s...", isoFilename, isoURL)
		if err := b2dutils.DownloadISO(commonIsoPath, isoFilename, isoURL); err != nil {
			return err

		}

	} else {
		// todo: check latest release URL, download if it's new
		// until then always use "latest"
		isoURL, err = b2dutils.GetLatestBoot2DockerReleaseURL()
		if err != nil {
			log.Warnf("Unable to check for the latest release: %s", err)
		}

		if _, err := os.Stat(commonIsoPath); os.IsNotExist(err) {
			log.Infof("Downloading %s to %s...", isoFilename, commonIsoPath)
			if err := b2dutils.DownloadISO(imgPath, isoFilename, isoURL); err != nil {
				return err
			}
		}

		isoDest := filepath.Join(d.storePath, isoFilename)
		if err := utils.CopyFile(commonIsoPath, isoDest); err != nil {
			return err
		}
	}

	log.Infof("Creating SSH key...")

	if err := ssh.GenerateSSHKey(d.sshKeyPath()); err != nil {
		return err
	}

	log.Infof("Creating Disk image...")

	if err := d.generateDiskImage(d.DiskSize); err != nil {
		return err
	}

	log.Infof("Starting QEMU VM...")

	if err := d.Start(); err != nil {
		return err
	}

	return nil
}

func getAvailableTCPPort() (int, error) {
	port := 0
	for i := 0; i <= 10; i++ {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		defer ln.Close()
		addr := ln.Addr().String()
		addrParts := strings.SplitN(addr, ":", 2)
		p, err := strconv.Atoi(addrParts[1])
		if err != nil {
			return 0, err
		}
		if p != 0 {
			port = p
			return port, nil
		}
		time.Sleep(1)
	}
	return 0, fmt.Errorf("unable to allocate tcp port")

}

func (d *Driver) Start() error {
	// fmt.Printf("Init qemu %s\n", i.VM)

	startCmd := []string{
		"-netdev", "user,id=network0",
		"-device", "virtio-net,netdev=network0",
		"-redir", fmt.Sprintf("tcp:%d::22", d.SSHPort),
		"-m", fmt.Sprintf("%d", d.Memory),
		"-boot", "d",
		"-cdrom", filepath.Join(d.storePath, "boot2docker.iso"),
		"-qmp", fmt.Sprintf("unix:%s,server,nowait", d.monitorPath()),
		"-netdev", fmt.Sprintf("bridge,id=network1,br=%s", d.NetworkBridge),
		"-device", "virtio-net,netdev=network1",
		"-daemonize",
	}

	// other options
	// "-enable-kvm" if its available
	if _, err := os.Stat("/dev/kvm"); err == nil {
		startCmd = append(startCmd, "-enable-kvm")
	}

	// last argument is always the name of the disk image
	startCmd = append(startCmd, d.diskPath())

	if stdout, stderr, err := cmdOutErr("qemu-system-x86_64", startCmd...); err != nil {
		fmt.Printf("OUTPUT: %s\n", stdout)
		fmt.Printf("ERROR: %s\n", stderr)
		return err;
	//if err := cmdStart("qemu-system-x86_64", startCmd...); err != nil {
	//	return err
	}
	log.Infof("Waiting for VM to start (ssh -p %d docker@localhost)...", d.SSHPort)

	//return nil
	//return ssh.WaitForTCP(fmt.Sprintf("localhost:%d", d.SSHPort))
	return WaitForTCPWithDelay(fmt.Sprintf("localhost:%d", d.SSHPort), time.Second)
}

func cmdOutErr(cmdStr string, args ...string) (string, string, error) {
	cmd := exec.Command(cmdStr, args...)
	log.Debugf("executing: %v %v", cmdStr, strings.Join(args, " "))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	stderrStr := stderr.String()
	log.Debugf("STDOUT: %v", stdout.String())
	log.Debugf("STDERR: %v", stderrStr)
	if err != nil {
		if ee, ok := err.(*exec.Error); ok && ee == exec.ErrNotFound {
			err = fmt.Errorf("Mystery!")
		}
	} else {
		// also catch error messages in stderr, even if the return code
		// looks OK
		if strings.Contains(stderrStr, "error:") {
			err = fmt.Errorf("%v %v failed: %v", cmdStr, strings.Join(args, " "), stderrStr)
		}
	}
	return stdout.String(), stderrStr, err
}

func cmdStart(cmdStr string, args ...string) error {
	cmd := exec.Command(cmdStr, args...)
	log.Debugf("executing: %v %v", cmdStr, strings.Join(args, " "))
	return cmd.Start()
}

func (d *Driver) Stop() error {
	// _, err := d.RunQMPCommand("stop")
	_, err := d.RunQMPCommand("system_powerdown")
	if err != nil {
       		return err
	}
	return nil
}

func (d *Driver) Remove() error {
	s, err := d.GetState()
	if err != nil {
		return err
	}
	if s == state.Running {
		if err := d.Kill(); err != nil {
			return err
		}
	}
	_, err = d.RunQMPCommand("quit")
	if err != nil {
       		return err
	}
	return nil
}

func (d *Driver) Restart() error {
	s, err := d.GetState()
	if err != nil {
		return err
	}

	if s == state.Running {
		if err := d.Stop(); err != nil {
			return err
		}
	}
	return d.Start()
}

func (d *Driver) Kill() error {
	// _, err := d.RunQMPCommand("quit")
	_, err := d.RunQMPCommand("system_powerdown")
	if err != nil {
       		return err
	}
	return nil
}

func (d *Driver) GetDockerConfigDir() string {
	return ""
}

func (d *Driver) GetSSHCommand(args ...string) (*exec.Cmd, error) {
	return ssh.GetSSHCommand("localhost", d.SSHPort, "docker", d.sshKeyPath(), args...), nil
}

func (d *Driver) sshKeyPath() string {
	return filepath.Join(d.storePath, "id_rsa")
}

func (d *Driver) publicSSHKeyPath() string {
	return d.sshKeyPath() + ".pub"
}

func (d *Driver) diskPath() string {
	return filepath.Join(d.storePath, "disk.qcow2")
}

func (d *Driver) monitorPath() string {
	return filepath.Join(d.storePath, "monitor")
}

// Make a boot2docker VM disk image.
func (d *Driver) generateDiskImage(size int) error {
	log.Debugf("Creating %d MB hard disk image...", size)

	magicString := "boot2docker, please format-me"

	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)

	// magicString first so the automount script knows to format the disk
	file := &tar.Header{Name: magicString, Size: int64(len(magicString))}
	if err := tw.WriteHeader(file); err != nil {
		return err
	}
	log.Infof("1")
	if _, err := tw.Write([]byte(magicString)); err != nil {
		return err
	}
	// .ssh/key.pub => authorized_keys
	log.Infof("2")
	file = &tar.Header{Name: ".ssh", Typeflag: tar.TypeDir, Mode: 0700}
	if err := tw.WriteHeader(file); err != nil {
		return err
	}
	log.Infof("3")
	pubKey, err := ioutil.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return err
	}
	log.Infof("4")
	file = &tar.Header{Name: ".ssh/authorized_keys", Size: int64(len(pubKey)), Mode: 0644}
	if err := tw.WriteHeader(file); err != nil {
		return err
	}
	log.Infof("5")
	if _, err := tw.Write([]byte(pubKey)); err != nil {
		return err
	}
	log.Infof("6")
	file = &tar.Header{Name: ".ssh/authorized_keys2", Size: int64(len(pubKey)), Mode: 0644}
	if err := tw.WriteHeader(file); err != nil {
		return err
	}
	log.Infof("7")
	if _, err := tw.Write([]byte(pubKey)); err != nil {
		return err
	}
	log.Infof("8")
	if err := tw.Close(); err != nil {
		return err
	}
	log.Infof("9")
	rawFile := fmt.Sprintf("%s.raw", d.diskPath())
	if err := ioutil.WriteFile(rawFile, buf.Bytes(), 0644); err != nil {
		return nil
	}
	log.Infof("10")
	if stdout, stderr, err := cmdOutErr("qemu-img", "convert", "-f", "raw", "-O", "qcow2", rawFile, d.diskPath()); err != nil {
		fmt.Printf("OUTPUT: %s\n", stdout)
		fmt.Printf("ERROR: %s\n", stderr)
		return err
	}
	log.Infof("11")
	if stdout, stderr, err := cmdOutErr("qemu-img", "resize", d.diskPath(), fmt.Sprintf("+%dMB", size)); err != nil {
		fmt.Printf("OUTPUT: %s\n", stdout)
		fmt.Printf("ERROR: %s\n", stderr)
		return err
	}
	log.Debugf("DONE writing to %s and %s", rawFile, d.diskPath())

	return nil
}

func (d *Driver) RunQMPCommand(command string) (map[string]interface{}, error) {

	// connect to monitor
	conn, err := net.Dial("unix", d.monitorPath())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// initial QMP response
	var buf [1024]byte
	nr, err := conn.Read(buf[:])
	if err != nil {
       		return nil, err
	}
	type qmpInitialResponse struct {
		QMP struct {
			Version struct {
				QEMU struct {
					Micro int  `json:"micro"`
					Minor int  `json:"minor"`
					Major int  `json:"major"`
				}  `json:"qemu"`
				Package string  `json:"package"`
			}  `json:"version"`
			Capabilities []string  `json:"capabilities"`
		}  `jason:"QMP"`
	}

	var initialResponse qmpInitialResponse
	json.Unmarshal(buf[:nr], &initialResponse)

	// run 'qmp_capabilities' to switch to command mode
	// { "execute": "qmp_capabilities" }
	type qmpCommand struct {
		Command string  `json:"execute"`
	}
	jsonCommand, err := json.Marshal(qmpCommand{Command: "qmp_capabilities" })
	if err != nil {
       		return nil, err
	}
	_, err = conn.Write(jsonCommand)
	if err != nil {
       		return nil, err
	}
	nr, err = conn.Read(buf[:])
	if err != nil {
       		return nil, err
	}
	type qmpResponse struct {
		Return map[string]interface{}  `json:"return"`
	}
	var response qmpResponse
	err = json.Unmarshal(buf[:nr], &response)
	if err != nil {
       		return nil, err
	}
	// expecting empty response
	if len(response.Return) != 0 {
       		return nil, fmt.Errorf("qmp_capabilities failed: %v", response.Return)
	}

	// { "execute": command }
	jsonCommand, err = json.Marshal(qmpCommand{Command: command })
	if err != nil {
       		return nil, err
	}
	_, err = conn.Write(jsonCommand)
	if err != nil {
       		return nil, err
	}
	nr, err = conn.Read(buf[:])
	if err != nil {
       		return nil, err
	}
	err = json.Unmarshal(buf[:nr], &response)
	if err != nil {
       		return nil, err
	}
	if strings.HasPrefix(command, "query-") {
        	return response.Return, nil
	}
	// non-query commands should return an empty response
	if len(response.Return) != 0 {
       		return nil, fmt.Errorf("%s failed: %v", command, response.Return)
	}
        return response.Return, nil
}

func WaitForTCPWithDelay(addr string, duration time.Duration) error {
	for {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			continue
		}
		defer conn.Close()
		if _, err = conn.Read(make([]byte, 1)); err != nil {
			time.Sleep(duration)
			continue
		}
		break
	}
	return nil
}
