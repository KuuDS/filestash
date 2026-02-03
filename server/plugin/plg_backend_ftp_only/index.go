package plg_backend_ftp_only

import (
	"fmt"
	"io"
	"io/fs"
	"net/textproto"
	"os"
	"regexp"
	"strings"
	"time"

	. "github.com/mickael-kerjean/filestash/server/common"

	"github.com/jlaffaye/ftp"
)

var FtpCache AppCache

// ftpFileInfo is an adapter to make ftp.Entry compatible with os.FileInfo interface
type ftpFileInfo struct {
	entry *ftp.Entry
}

func (f *ftpFileInfo) Name() string       { return f.entry.Name }
func (f *ftpFileInfo) Size() int64        { return int64(f.entry.Size) }
func (f *ftpFileInfo) Mode() fs.FileMode {
	if f.IsDir() {
		return fs.ModeDir | 0755
	}
	return 0644
}
func (f *ftpFileInfo) ModTime() time.Time { return f.entry.Time }
func (f *ftpFileInfo) IsDir() bool        { return f.entry.Type == ftp.EntryTypeFolder }
func (f *ftpFileInfo) Sys() interface{}   { return f.entry }

type Ftp struct {
	client *ftp.ServerConn
}

func init() {
	Backend.Register("ftp", Ftp{})

	FtpCache = NewAppCache(2, 1)
	FtpCache.OnEvict(func(key string, value interface{}) {
		c := value.(*Ftp)
		c.Close()
	})
}

func (f Ftp) Init(params map[string]string, app *App) (IBackend, error) {
	if c := FtpCache.Get(params); c != nil {
		d := c.(*Ftp)
		return d, nil
	}
	if params["hostname"] == "" {
		params["hostname"] = "localhost"
	}

	if params["port"] == "" {
		params["port"] = "21"
	}
	if params["username"] == "" {
		params["username"] = "anonymous"
	}
	if params["username"] == "anonymous" && params["password"] == "" {
		params["password"] = "anonymous"
	}

	var backend *Ftp = nil
	hostname := fmt.Sprintf("%s:%s", strings.TrimPrefix(params["hostname"], "ftp://"), params["port"])

	client, err := ftp.Dial(hostname, ftp.DialWithTimeout(10*time.Second))
	if err != nil {
		return backend, err
	}
	if err := client.Login(params["username"], params["password"]); err != nil {
		client.Quit()
		return backend, ErrAuthenticationFailed
	}
	if _, err := client.List("/"); err != nil {
		client.Quit()
		return backend, ErrAuthenticationFailed
	}
	backend = &Ftp{client}
	FtpCache.Set(params, backend)
	return backend, nil
}

func (f Ftp) LoginForm() Form {
	return Form{
		Elmnts: []FormElement{
			FormElement{
				Name:  "type",
				Type:  "hidden",
				Value: "ftp",
			},
			FormElement{
				Name:        "hostname",
				Type:        "text",
				Placeholder: "Hostname*",
			},
			FormElement{
				Name:        "username",
				Type:        "text",
				Placeholder: "Username",
			},
			FormElement{
				Name:        "password",
				Type:        "password",
				Placeholder: "Password",
			},
			FormElement{
				Name:        "advanced",
				Type:        "enable",
				Placeholder: "Advanced",
				Target:      []string{"ftp_path", "ftp_port", "ftp_conn", "ftp_disable_ftps"},
			},
			FormElement{
				Id:          "ftp_path",
				Name:        "path",
				Type:        "text",
				Placeholder: "Path",
			},
			FormElement{
				Id:          "ftp_port",
				Name:        "port",
				Type:        "number",
				Placeholder: "Port",
			},
			FormElement{
				Id:          "ftp_conn",
				Name:        "conn",
				Type:        "number",
				Placeholder: "Number of connections",
			},
			FormElement{
				Id:          "ftp_conn",
				Name:        "conn",
				Type:        "number",
				Placeholder: "Number of connections",
			},
			FormElement{
				Id:   "ftp_disable_ftps",
				Name: "Disable FTPS",
				Type: "select",
				Opts: []string{"DEBUG", "INFO", "WARNING", "ERROR"},
			},
		},
	}
}

func (f Ftp) Home() (string, error) {
	return f.client.CurrentDir()
}

func (f Ftp) Ls(path string) ([]os.FileInfo, error) {
	entries, err := f.client.List(path)
	if err != nil {
		return nil, err
	}
	files := make([]os.FileInfo, len(entries))
	for i, entry := range entries {
		files[i] = &ftpFileInfo{entry: entry}
	}
	return files, nil
}

func (f Ftp) Cat(path string) (io.ReadCloser, error) {
	return f.client.Retr(path)
}

func (f Ftp) Mkdir(path string) error {
	return f.client.MakeDir(path)
}

func (f Ftp) Rm(path string) error {
	isDirectory := func(p string) bool {
		return regexp.MustCompile(`\/$`).MatchString(p)
	}
	transformError := func(e error) error {
		// For some reasons bsftp is struggling with the library
		// sometimes returning a 200 OK
		if e == nil {
			return nil
		}
		// Check for successful FTP codes (2xx)
		if protoErr, ok := e.(*textproto.Error); ok {
			if protoErr.Code >= 200 && protoErr.Code < 300 {
				return nil
			}
		}
		return e
	}
	if isDirectory(path) {
		entries, err := f.Ls(path)
		if transformError(err) != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				err = f.Rm(path + entry.Name() + "/")
				if transformError(err) != nil {
					return err
				}
			} else {
				err = f.Rm(path + entry.Name())
				if transformError(err) != nil {
					return err
				}
			}
		}
		err := f.client.RemoveDir(path)
		return transformError(err)
	}
	err := f.client.Delete(path)
	return transformError(err)
}

func (f Ftp) Mv(from string, to string) error {
	return f.client.Rename(from, to)
}

func (f Ftp) Touch(path string) error {
	return f.client.Stor(path, strings.NewReader(""))
}

func (f Ftp) Save(path string, file io.Reader) error {
	return f.client.Stor(path, file)
}

func (f Ftp) Close() error {
	return f.client.Quit()
}
