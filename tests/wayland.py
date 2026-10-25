#!/usr/bin/env python3
"""Native Wayland UI/menu QA in a disposable nested DomeD compositor."""
import hashlib,json,os,re,signal,socket,ssl,subprocess,sys,tempfile,time,urllib.request
from pathlib import Path
from Xlib import X,XK,display
from Xlib.ext import xtest
from PIL import Image
signal.pthread_sigmask(signal.SIG_SETMASK,[])
if os.environ.get('DOME_IDENTITIES_WAYLAND_BUS')!='1':
 os.execvpe('dbus-run-session',['dbus-run-session','--',sys.executable,*sys.argv],{**os.environ,'DOME_IDENTITIES_WAYLAND_BUS':'1'})
root=Path(__file__).resolve().parents[1];out=root/'build/test-artifacts/wayland';out.mkdir(parents=True,exist_ok=True)
compositor=Path(os.environ.get('DOME_IDENTITIES_COMPOSITOR',root.parent/'DomeD/target/release/dome-compositor'))
assert compositor.exists(),'Provide a built nested compositor using DOME_IDENTITIES_COMPOSITOR'
children=[];logs=[]
def start(args,env,name,**kwargs):
 log=(out/(name+'.log')).open('w');logs.append(log);process=subprocess.Popen(args,env=env,stdout=log,stderr=log,**kwargs);children.append(process);return process
def wait(predicate,seconds=20):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  try:
   result=predicate()
   if result:return result
  except (OSError,ValueError,KeyError,StopIteration):pass
  time.sleep(.05)
 raise AssertionError('Timed out; inspect '+str(out))
try:
 with tempfile.TemporaryDirectory(prefix='dome-identities-wayland-') as folder:
  tmp=Path(folder);tmp.chmod(0o700);catalog=tmp/'data/de-xr/identities/index.json';catalog.parent.mkdir(parents=True,mode=0o700)
  cert=tmp/'fixture.pem';key=tmp/'fixture.key'
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/UID=fixture/CN=Wayland fixture','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);key.chmod(0o600)
  fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest();catalog.write_text(json.dumps({'version':1,'identities':[{'id':fingerprint,'name':'Wayland fixture','certificate':str(cert),'key':str(key)}]}));catalog.chmod(0o600);original=key.read_bytes()
  read,write=os.pipe();start(['Xvfb','-displayfd',str(write),'-screen','0','1600x1000x24','-nolisten','tcp','-noreset'],os.environ.copy(),'xvfb',pass_fds=(write,));os.close(write)
  with os.fdopen(read) as source:screen=':'+source.readline().strip()
  with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
  base_env={key:value for key,value in os.environ.items() if not key.startswith('DOME_')}
  env={**base_env,'HOME':str(tmp),'GNUPGHOME':str(tmp/'gnupg'),'DISPLAY':screen,'XDG_RUNTIME_DIR':str(tmp),'XDG_CONFIG_HOME':str(tmp/'config'),'XDG_CACHE_HOME':str(tmp/'cache'),'XDG_STATE_HOME':str(tmp/'state'),'XDG_DATA_HOME':str(tmp/'data'),'XDG_CURRENT_DESKTOP':'Dome','DOME_LOGIN_SESSION':'0','DOME_SESSION_RESTORE':'0','DOME_START_XR':'0','DOME_APPEARANCE_SERVICE':'0','DOME_RENDERER':'gles','DOME_PREVIEW_PORT':str(port),'LIBGL_ALWAYS_SOFTWARE':'1','RUST_LOG':'warn','LD_LIBRARY_PATH':'/opt/fltk-vr/toolkit/lib'}
  for setting in ('TRAY','KDECONNECT','KWALLET','POLKIT','IME','XWAYLAND'):env['DOME_START_'+setting]='0'
  for setting in ('WAYLAND_DISPLAY','WAYLAND_SOCKET','QT_QPA_PLATFORM','GTK_MODULES'):env.pop(setting,None)
  nested=start([str(compositor),'--backend','nested'],env,'compositor')
  http=urllib.request.build_opener(urllib.request.ProxyHandler({}));base=f'http://127.0.0.1:{port}'
  def request(path,data=None):
   body=None if data is None else json.dumps(data).encode()
   return http.open(urllib.request.Request(base+path,data=body,headers={'Content-Type':'application/json'}),timeout=2)
  def scene():
   with request('/api/state') as response:return json.load(response)['scene']
  wait(lambda:scene()['source']=='wayland')
  socket_name=wait(lambda:re.search(r'Dome Wayland socket: (\S+)',(out/'compositor.log').read_text()))[1]
  app=start([str(root/'build/dome-identities')],{**env,'DISPLAY':'','WAYLAND_DISPLAY':socket_name,'FLTK_BACKEND':'wayland','WAYLAND_DEBUG':'1'},'manager')
  window=wait(lambda:next((window for window in scene()['windows'] if window['title']=='Dome Identities'),None));assert window['app_id']=='org.domed.Identities'
  def registered_items():
   return subprocess.check_output(['gdbus','call','--session','--dest','org.kde.StatusNotifierWatcher','--object-path','/StatusNotifierWatcher','--method','org.freedesktop.DBus.Properties.Get','org.kde.StatusNotifierWatcher','RegisteredStatusNotifierItems'],text=True,timeout=3)
  service=wait(lambda:re.search(r'(:[0-9.]+)/StatusNotifierItem',registered_items()))[1]
  def call(interface,method,*args,path='/StatusNotifierItem'):
   return subprocess.check_output(['gdbus','call','--session','--dest',service,'--object-path',path,'--method',interface+'.'+method,'--',*args],text=True,timeout=3)
  path=re.search("'([^']+)'",call('org.freedesktop.DBus.Properties','Get','org.kde.StatusNotifierItem','Menu')).group(1)
  def command(name):
   layout=call('com.canonical.dbusmenu','GetLayout','0','-1','[]',path=path)
   item=re.search(r"\((\d+), \{'label': <'"+re.escape(name)+"'>",layout);assert item,name
   call('com.canonical.dbusmenu','Event',item[1],'clicked','<0>','0',path=path)
  time.sleep(.3);assert '.set_address(' not in (out/'manager.log').read_text()
  trace=(out/'manager.log').read_text();assert 'xdg_wm_base' in trace and 'wl_surface' in trace and app.poll() is None
  request('/api/action',{'op':'focus','id':window['id']}).close()
  xd=display.Display(screen);host=wait(lambda:next((window for window in xd.screen().root.query_tree().children if str(window.get_wm_name()or'').startswith('Dome')),None));host.set_input_focus(X.RevertToParent,X.CurrentTime);xd.sync()
  def press(name):
   code=xd.keysym_to_keycode(XK.string_to_keysym(name))
   for kind in (X.KeyPress,X.KeyRelease):xtest.fake_input(xd,kind,code);xd.sync();time.sleep(.05)
  def screenshot(name):
   geometry=host.get_geometry();raw=host.get_image(0,0,geometry.width,geometry.height,X.ZPixmap,0xffffffff);Image.frombytes('RGB',(geometry.width,geometry.height),raw.data,'raw','BGRX').save(out/name)
  def popup_ids():return {p['id'] for p in scene().get('popups',[]) if p.get('root')==window['id']}
  def motion(px,py):
   g=host.get_geometry()
   xtest.fake_input(xd,X.MotionNotify,x=int(g.x+px-1),y=int(g.y+py));xd.sync();time.sleep(.05)
   xtest.fake_input(xd,X.MotionNotify,x=int(g.x+px),y=int(g.y+py));xd.sync();time.sleep(.1)
  def click(px,py,button=1):
   motion(px,py);xtest.fake_input(xd,X.ButtonPress,button);xtest.fake_input(xd,X.ButtonRelease,button);xd.sync();time.sleep(.2)
  rectangle=window['desktop']
  click(rectangle['x']+250,rectangle['y']+30);family=wait(popup_ids);time.sleep(.2)
  motion(rectangle['x']+950,rectangle['y']+440);time.sleep(.6);assert popup_ids()==family,'Native store popup closed on parent-content cursor leave'
  motion(5,705);time.sleep(.6);assert popup_ids()==family,'Native store popup closed on empty-space cursor leave'
  press('Escape');wait(lambda:not popup_ids())
  def shell():
   with request('/api/xr-shell') as response:return json.load(response)
  # This private fixture uses the default nine-character clock, clamped to
  # 176 px, plus the 44 px language selector; identities is its last SNI.
  tray_x=host.get_geometry().width-176-44-14
  click(tray_x,18,3);tray_height=wait(lambda:shell()['top'] if shell()['top']>36 else None)
  screenshot('tray-owned-actions.png')
  motion(rectangle['x']+950,rectangle['y']+440);time.sleep(.7)
  assert shell()['top']==tray_height,'Tray action popup closed on parent-content leave'
  motion(5,705);time.sleep(.7)
  assert shell()['top']==tray_height,'Tray action popup closed on empty-space leave'
  press('Escape');wait(lambda:shell()['top']==36)
  import threading
  pulse_stop=threading.Event()
  def pulse():
   while not pulse_stop.is_set():
    try:request('/api/xr-session',{'visible':True,'focused':True,'head':{'position_m':[0,1.4,0],'orientation_xyzw':[0,0,0,1]},'horizontal_fov_deg':100,'mouse_viewport':[-.4,.47,-.32,.36]}).close()
    except OSError:pass
    pulse_stop.wait(.1)
  heartbeat=threading.Thread(target=pulse,daemon=True);heartbeat.start()
  try:
   wait(lambda:json.load(request('/api/xr-control'))['input_realm']=='xr')
   # XR owns a fixed 1024x768 shell, independent of desktop dimensions.
   request('/api/xr-input',{'events':[{'kind':'motion','id':0,'uv':[(1024-176-44-14)/1024,18/36]}],'actions':[]}).close();time.sleep(.2)
   request('/api/xr-input',{'events':[{'kind':'button','button':273,'pressed':True},{'kind':'button','button':273,'pressed':False}],'actions':[]}).close()
   wait(lambda:shell()['top']>36)
   request('/api/xr-input',{'events':[{'kind':'motion','id':window['id'],'uv':[.9,.8]}],'actions':[]}).close();time.sleep(.7)
   assert shell()['top']>36,'XR-opened tray popup closed on parent-content leave'
   request('/api/xr-input',{'events':[{'kind':'leave'}],'actions':[]}).close();time.sleep(.7)
   assert shell()['top']>36,'XR-opened tray popup closed on empty-space leave'
   press('Escape');wait(lambda:shell()['top']==36)
   request('/api/xr-input',{'events':[],'actions':[{'op':'focus','id':window['id']}]}).close()
   request('/api/xr-input',{'events':[{'kind':'motion','id':window['id'],'uv':[250/rectangle['w'],30/rectangle['h']]}],'actions':[]}).close();time.sleep(.2)
   request('/api/xr-input',{'events':[{'kind':'button','button':272,'pressed':True},{'kind':'button','button':272,'pressed':False}],'actions':[]}).close()
   xr_family=wait(popup_ids);time.sleep(.3)
   request('/api/xr-input',{'events':[{'kind':'motion','id':window['id'],'uv':[.9,.8]}],'actions':[]}).close();time.sleep(.7)
   assert popup_ids()==xr_family,'Native store popup closed on XR parent-content cursor leave'
   request('/api/xr-input',{'events':[{'kind':'leave'}],'actions':[]}).close();time.sleep(.7)
   assert popup_ids()==xr_family,'Native store popup closed on XR empty-space cursor leave'
   press('Escape');wait(lambda:not popup_ids())

  finally:
   pulse_stop.set();heartbeat.join(timeout=2);request('/api/xr-session',{'visible':False,'focused':False}).close()
  layout=call('com.canonical.dbusmenu','GetLayout','0','-1','[]',path=path);assert "'File'" not in layout and 'Export public...' in layout
  (out/'popup-cursor-leave.json').write_text(json.dumps({'passed':True,'compositor_sha256':hashlib.sha256(compositor.read_bytes()).hexdigest(),'toolkit_sha256':hashlib.sha256(Path('/opt/fltk-vr/toolkit/lib/libfltk.so.1.4.5').read_bytes()).hexdigest(),'desktop_parent_leave':True,'desktop_empty_leave':True,'xr_parent_leave':True,'xr_empty_leave':True,'escape_dismissal':True,'tray_popup_desktop_parent_leave':True,'tray_popup_desktop_empty_leave':True,'tray_popup_xr_parent_leave':True,'tray_popup_xr_empty_leave':True,'tray_popup_xr_open_trigger':'synthetic-xr-context-click','flat_tray_menu':True,'window_menu_association':False},indent=2)+'\n')
  time.sleep(.4);screenshot('native-wayland.png')
  started=time.monotonic();command('Create...');assert time.monotonic()-started<1.0
  time.sleep(.3)
  for letter in 'fixture':press(letter)
  press('Return');time.sleep(.3);screenshot('mailbox-prompt.png');press('Escape');time.sleep(.2)
  command('Close to tray');wait(lambda:not any(window['title']=='Dome Identities' for window in scene()['windows']))
  call('org.kde.StatusNotifierItem','Activate','0','0');wait(lambda:any(window['title']=='Dome Identities' for window in scene()['windows']))
  command('Refresh');time.sleep(.2);command('Quit');assert app.wait(timeout=5)==0
  assert key.read_bytes()==original and len(json.loads(catalog.read_text())['identities'])==1
  xd.close();print('PASS native Wayland mapping/app ID, tray-owned flat commands and cursor-leave popup retention, native prompts, canceled creation, tray restoration, worker refresh and clean shutdown with fixture keys unchanged')
finally:
 for child in reversed(children):
  if child.poll() is None:
   child.terminate()
   try:child.wait(timeout=5)
   except subprocess.TimeoutExpired:child.kill();child.wait()
 for log in logs:log.close()
