package plg_backend_ftp

import (
	"context"
	"crypto/tls"
	"fmt"
	. "github.com/mickael-kerjean/filestash/server/common"
	"github.com/jlaffaye/ftp"
	"io"
	"io/fs"
	"net/textproto"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
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
	p      map[string]string
	wg     *sync.WaitGroup
	ctx    context.Context
}

func init() {
	Backend.Register("ftp", Ftp{})

	FtpCache = NewAppCache(2, 1)
	FtpCache.OnEvict(func(key string, value interface{}) {
		c := value.(*Ftp)
		if c == nil {
			Log.Warning("plg_backend_ftp::ftp is nil on close")
			return
		} else if c.wg == nil {
			Log.Warning("plg_backend_ftp::wg is nil on close")
			c.Close()
			return
		}
		c.wg.Wait()
		Log.Debug("plg_backend_ftp::vacuum")
		c.Close()
	})
}

func (f Ftp) Init(params map[string]string, app *App) (IBackend, error) {
	if c := FtpCache.Get(params); c != nil {
		d := c.(*Ftp)
		if d == nil {
			Log.Warning("plg_backend_ftp::ftp is nil on get")
			return nil, ErrInternal
		} else if d.wg == nil {
			Log.Warning("plg_backend_ftp::wg is nil on get")
			return nil, ErrInternal
		}
		d.wg.Add(1)
		d.ctx = app.Context
		go func() {
			<-d.ctx.Done()
			d.wg.Done()
		}()
		return d, nil
	}
	if params["hostname"] == "" {
		params["hostname"] = "localhost"
	}

	if params["port"] == "" {
		params["port"] = "21"
	}
	if params["username"] == "" {
		params["acl"] = "r"
		params["username"] = "anonymous"
	}
	if params["username"] == "anonymous" && params["password"] == "" {
		params["password"] = "anonymous"
	}

	connectStrategy := []string{"ftp", "ftps::implicit", "ftps::explicit"}
	if strings.HasPrefix(params["hostname"], "ftp://") {
		connectStrategy = []string{"ftp"}
		params["hostname"] = strings.TrimPrefix(params["hostname"], "ftp://")
	} else if strings.HasPrefix(params["hostname"], "ftps://") {
		connectStrategy = []string{"ftps::implicit", "ftps::explicit"}
		params["hostname"] = strings.TrimPrefix(params["hostname"], "ftps://")
	}

	var backend *Ftp = nil
	hostname := fmt.Sprintf("%s:%s", params["hostname"], params["port"])
	
	dialOpts := func(timeout time.Duration, withTLS bool, tlsMode string) []ftp.DialOption {
		opts := []ftp.DialOption{
			ftp.DialWithTimeout(timeout),
		}
		if withTLS {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         params["hostname"],
			}
			if tlsMode == "implicit" {
				opts = append(opts, ftp.DialWithTLS(tlsConfig))
			} else {
				opts = append(opts, ftp.DialWithExplicitTLS(tlsConfig))
			}
		}
		return opts
	}
	
	for i := 0; i < len(connectStrategy); i++ {
		if connectStrategy[i] == "ftp" {
			client, err := ftp.Dial(hostname, dialOpts(5*time.Second, false, "")...)
			if err != nil {
				Log.Debug("plg_backend_ftp::ftp dial %s", err.Error())
				continue
			}
			if err := client.Login(params["username"], params["password"]); err != nil {
				client.Quit()
				Log.Debug("plg_backend_ftp::ftp login %s", err.Error())
				continue
			}
			if _, err := client.List("/"); err != nil {
				client.Quit()
				Log.Debug("plg_backend_ftp::ftp verify %s", err.Error())
				continue
			}
			client.Quit()
			client, err = ftp.Dial(hostname, dialOpts(60*time.Second, false, "")...)
			if err != nil {
				continue
			}
			if err := client.Login(params["username"], params["password"]); err != nil {
				client.Quit()
				continue
			}
			params["mode"] = connectStrategy[i]
			backend = &Ftp{client, params, nil, app.Context}
			break
		} else if connectStrategy[i] == "ftps::implicit" {
			client, err := ftp.Dial(hostname, dialOpts(60*time.Second, true, "implicit")...)
			if err != nil {
				Log.Debug("plg_backend_ftp::ftps::implicit dial %s", err.Error())
				continue
			}
			if err := client.Login(params["username"], params["password"]); err != nil {
				client.Quit()
				Log.Debug("plg_backend_ftp::ftps::implicit login %s", err.Error())
				continue
			}
			if _, err := client.List("/"); err != nil {
				Log.Debug("plg_backend_ftp::ftps::implicit verify %s", err.Error())
				client.Quit()
				continue
			}
			params["mode"] = connectStrategy[i]
			backend = &Ftp{client, params, nil, app.Context}
			break
		} else if connectStrategy[i] == "ftps::explicit" {
			client, err := ftp.Dial(hostname, dialOpts(5*time.Second, true, "explicit")...)
			if err != nil {
				Log.Debug("plg_backend_ftp::ftps::explicit dial '%s'", err.Error())
				continue
			}
			if err := client.Login(params["username"], params["password"]); err != nil {
				client.Quit()
				Log.Debug("plg_backend_ftp::ftps::explicit login %s", err.Error())
				continue
			}
			if _, err := client.List("/"); err != nil {
				Log.Debug("plg_backend_ftp::ftps::explicit verify %s", err.Error())
				client.Quit()
				continue
			}
			client.Quit()
			client, err = ftp.Dial(hostname, dialOpts(60*time.Second, true, "explicit")...)
			if err != nil {
				continue
			}
			if err := client.Login(params["username"], params["password"]); err != nil {
				client.Quit()
				continue
			}
			params["mode"] = connectStrategy[i]
			backend = &Ftp{client, params, nil, app.Context}
			break
		}
	}
	if backend == nil {
		return nil, ErrAuthenticationFailed
	}
	backend.wg = new(sync.WaitGroup)
	backend.wg.Add(1)
	backend.ctx = app.Context
	go func() {
		<-backend.ctx.Done()
		backend.wg.Done()
	}()
	FtpCache.Set(params, backend)
	return backend, nil
}

func (f Ftp) LoginForm() Form {
	return Form{
		Elmnts: []FormElement{
			{
				Name:  "type",
				Type:  "hidden",
				Value: "ftp",
			},
			{
				Name:        "hostname",
				Type:        "text",
				Placeholder: "Hostname*",
			},
			{
				Name:        "username",
				Type:        "text",
				Placeholder: "Username",
			},
			{
				Name:        "password",
				Type:        "password",
				Placeholder: "Password",
			},
			{
				Name:        "advanced",
				Type:        "enable",
				Placeholder: "Advanced",
				Target:      []string{"ftp_path", "ftp_port", "ftp_conn"},
			},
			{
				Id:          "ftp_path",
				Name:        "path",
				Type:        "text",
				Placeholder: "Path",
			},
			{
				Id:          "ftp_port",
				Name:        "port",
				Type:        "number",
				Placeholder: "Port",
			},
			{
				Id:          "ftp_conn",
				Name:        "conn",
				Type:        "number",
				Placeholder: "Number of connections",
			},
		},
	}
}

func (f Ftp) Meta(path string) Metadata {
	if f.p["acl"] == "r" {
		return Metadata{
			CanCreateFile:      NewBool(false),
			CanCreateDirectory: NewBool(false),
			CanRename:          NewBool(false),
			CanMove:            NewBool(false),
			CanUpload:          NewBool(false),
			CanDelete:          NewBool(false),
		}
	}
	return Metadata{}
}

func (f Ftp) Home() (home string, err error) {
	f.Execute(func(client *ftp.ServerConn) error {
		home, err = client.CurrentDir()
		return err
	})
	return home, err
}

func (f Ftp) Ls(path string) (files []os.FileInfo, err error) {
	f.Execute(func(client *ftp.ServerConn) error {
		entries, listErr := client.List(path)
		if listErr != nil {
			err = listErr
			return listErr
		}
		files = make([]os.FileInfo, len(entries))
		for i, entry := range entries {
			files[i] = &ftpFileInfo{entry: entry}
		}
		return nil
	})
	return files, err
}

func (f Ftp) Cat(path string) (reader io.ReadCloser, err error) {
	f.Execute(func(client *ftp.ServerConn) error {
		resp, catErr := client.Retr(path)
		if catErr != nil {
			err = catErr
			return catErr
		}
		reader = resp
		return nil
	})
	return reader, err
}

func (f Ftp) Stat(path string) (finfo os.FileInfo, err error) {
	f.Execute(func(client *ftp.ServerConn) error {
		entry, statErr := client.GetEntry(path)
		if statErr != nil {
			err = statErr
			return statErr
		}
		finfo = &ftpFileInfo{entry: entry}
		return nil
	})
	if err == nil {
		return finfo, err
	}
	// Check if it's a not found error (550 code)
	if protoErr, ok := err.(*textproto.Error); ok && protoErr.Code == 550 {
		return nil, ErrNotFound
	}
	return nil, ErrNotImplemented
}

func (f Ftp) Mkdir(path string) (err error) {
	f.Execute(func(client *ftp.ServerConn) error {
		err = client.MakeDir(path)
		return err
	})
	return err
}

func (f Ftp) Rm(path string) (err error) {
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
	var recursiveDelete func(client *ftp.ServerConn, _path string) error
	recursiveDelete = func(client *ftp.ServerConn, _path string) error {
		if isDirectory(_path) {
			entries, err := client.List(_path)
			if transformError(err) != nil {
				return err
			}
			for _, entry := range entries {
				if entry.Type == ftp.EntryTypeFolder {
					err = recursiveDelete(client, _path+entry.Name+"/")
					if transformError(err) != nil {
						return err
					}
				} else {
					err = recursiveDelete(client, _path+entry.Name)
					if transformError(err) != nil {
						return err
					}
				}
			}
			err = client.RemoveDir(_path)
			return transformError(err)
		}
		err := client.Delete(_path)
		return transformError(err)
	}
	f.Execute(func(client *ftp.ServerConn) error {
		err = recursiveDelete(client, path)
		return err
	})
	return err
}

func (f Ftp) Mv(from string, to string) (err error) {
	f.Execute(func(client *ftp.ServerConn) error {
		err = client.Rename(from, to)
		return err
	})
	return err
}

func (f Ftp) Touch(path string) (err error) {
	f.Execute(func(client *ftp.ServerConn) error {
		err = client.Stor(path, strings.NewReader(""))
		return err
	})
	return err
}

func (f Ftp) Save(path string, file io.Reader) (err error) {
	f.Execute(func(client *ftp.ServerConn) error {
		err = client.Stor(path, file)
		return err
	})
	return err
}

func (f Ftp) Close() error {
	return f.client.Quit()
}

func (f Ftp) Execute(fn func(*ftp.ServerConn) error) {
	err := fn(f.client)
	// Check for connection errors that require reconnection
	if err != nil {
		reconnect := false
		// Check for FTP 421 error (service not available, closing control connection)
		if protoErr, ok := err.(*textproto.Error); ok && protoErr.Code == 421 {
			reconnect = true
		}
		// Check for I/O errors
		if !reconnect && (strings.Contains(err.Error(), "EOF") || 
			strings.Contains(err.Error(), "broken pipe") ||
			strings.Contains(err.Error(), "connection reset")) {
			reconnect = true
		}
		
		if reconnect {
			f.Close()
			FtpCache.Set(f.p, nil)
			if b, err := f.Init(f.p, &App{Context: f.ctx}); err == nil {
				fn(b.(*Ftp).client)
			}
		}
	}
}
