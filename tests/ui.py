#!/usr/bin/env python3
"""Private bus/display UI and tray QA. Does not access user identities."""
import asyncio,hashlib,json,os,pathlib,re,signal,ssl,subprocess,sys,tempfile,time
from pathlib import Path
if '--watcher' in sys.argv:
 from gi.repository import Gio,GLib
 connection=Gio.bus_get_sync(Gio.BusType.SESSION,None)
 registered_services=[]
 xml='<node><interface name="org.kde.StatusNotifierWatcher"><method name="RegisterStatusNotifierItem"><arg type="s" direction="in"/></method><property name="RegisteredStatusNotifierItems" type="as" access="read"/></interface></node>'
 info=Gio.DBusNodeInfo.new_for_xml(xml)
 def registered(connection,sender,path,interface,method,parameters,invocation):
  service=parameters.unpack()[0];registered_services.append(service+'/StatusNotifierItem');Path(sys.argv[-1]).write_text(service);invocation.return_value(None)
 def property_value(connection,sender,path,interface,name):return GLib.Variant('as',registered_services)
 connection.register_object('/StatusNotifierWatcher',info.interfaces[0],registered,property_value,None)
 Gio.bus_own_name_on_connection(connection,'org.kde.StatusNotifierWatcher',Gio.BusNameOwnerFlags.NONE,None,None)
 Gio.bus_own_name_on_connection(connection,'com.canonical.AppMenu.Registrar',Gio.BusNameOwnerFlags.NONE,None,None)
 print('ready',flush=True);GLib.MainLoop().run();sys.exit()
from Xlib import X,display
from Xlib.ext import xtest
from PIL import Image
signal.pthread_sigmask(signal.SIG_SETMASK,[])
if os.environ.get('DOME_IDENTITIES_TEST_BUS')!='1':os.execvpe('dbus-run-session',['dbus-run-session','--',sys.executable,*sys.argv],{**os.environ,'DOME_IDENTITIES_TEST_BUS':'1'})
root=Path(__file__).resolve().parents[1];binary=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else root/'build/dome-identities';out=root/'build/test-artifacts';out.mkdir(parents=True,exist_ok=True)
def wait(fn,seconds=10):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  result=fn()
  if result:return result
  time.sleep(.05)
 raise AssertionError('UI timed out')
with tempfile.TemporaryDirectory(prefix='dome-identities-ui-') as temporary:
 tmp=Path(temporary);data=tmp/'data';catalog=data/'de-xr/identities/index.json';catalog.parent.mkdir(parents=True,mode=0o700);cert=tmp/'fixture.pem';key=tmp/'fixture.key'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/UID=fixture/CN=Fixture','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);os.chmod(key,0o600)
 fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest();catalog.write_text(json.dumps({'version':1,'identities':[{'id':fingerprint,'name':'Fixture identity','certificate':str(cert),'key':str(key),'address':'fixture@localhost'}]}));os.chmod(catalog,0o600)
 original=key.read_bytes();read,write=os.pipe();xvfb=subprocess.Popen(['Xvfb','-displayfd',str(write),'-screen','0','1400x900x24','-nolisten','tcp'],pass_fds=(write,),stderr=subprocess.DEVNULL);os.close(write)
 with os.fdopen(read) as source:screen=':'+source.readline().strip()
 env={**os.environ,'HOME':str(tmp),'GNUPGHOME':str(tmp/'gnupg'),'XDG_DATA_HOME':str(data),'XDG_CONFIG_HOME':str(tmp/'config'),'XDG_CACHE_HOME':str(tmp/'cache'),'XDG_STATE_HOME':str(tmp/'state'),'XDG_CURRENT_DESKTOP':'Dome','DISPLAY':screen,'FLTK_BACKEND':'x11','LIBGL_ALWAYS_SOFTWARE':'1','LD_LIBRARY_PATH':'/opt/fltk-vr/toolkit/lib'};env.pop('WAYLAND_DISPLAY',None)
 watcher=subprocess.Popen([sys.executable,__file__,'--watcher',str(tmp/'registered')],stdout=subprocess.PIPE,text=True);assert watcher.stdout.readline().strip()=='ready'
 log=(out/'manager.log').open('w');app=subprocess.Popen([str(binary)],env=env,stdout=log,stderr=log);xd=display.Display(screen)
 try:
  def ready():
   if app.poll() is not None:raise AssertionError('Manager exited '+str(app.returncode))
   return (tmp/'registered').exists()
  wait(ready);service=(tmp/'registered').read_text()
  def call(interface,method,*args,path='/StatusNotifierItem'):
   return subprocess.check_output(['gdbus','call','--session','--dest',service,'--object-path',path,'--method',interface+'.'+method,'--',*args],text=True,timeout=3)
  def prop(name):return call('org.freedesktop.DBus.Properties','Get','org.kde.StatusNotifierItem',name)
  assert 'dome-identities' in prop('Id');assert '24, 24' in prop('IconPixmap')
  menu=re.search("'([^']+)'",prop('Menu')).group(1)
  layout=call('com.canonical.dbusmenu','GetLayout','0','-1','[]',path=menu);assert 'Import...' in layout and 'Close to tray' in layout
  def window():return next((w for w in xd.screen().root.query_tree().children if w.get_wm_name()=='Dome Identities'),None)
  w=wait(window);time.sleep(.5)
  g=w.get_geometry();xtest.fake_input(xd,X.MotionNotify,x=g.x+90,y=g.y+157)
  xtest.fake_input(xd,X.ButtonPress,1);xtest.fake_input(xd,X.ButtonRelease,1);xd.sync();time.sleep(.2)
  g=w.get_geometry();raw=xd.screen().root.get_image(g.x,g.y,g.width,g.height,X.ZPixmap,0xffffffff);Image.frombytes('RGB',(g.width,g.height),raw.data,'raw','BGRX').save(out/'manager.png')
  def command(name):
   item=re.search(r"\((\d+), \{'label': <'"+re.escape(name)+"'>",layout);assert item;call('com.canonical.dbusmenu','Event',item[1],'clicked','<0>','0',path=menu)
  command('Close to tray');wait(lambda:window() is None)
  call('org.kde.StatusNotifierItem','Activate','0','0');w=wait(window);wait(lambda:w.get_attributes().map_state==X.IsViewable)
  tray_driver=Path(os.environ.get('DOME_IDENTITIES_TRAY_DRIVER',root.parent/'DomeD/build/tray/tray-service-driver'))
  if tray_driver.exists():
   driver=subprocess.Popen([str(tray_driver)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,env=env)
   try:
    def tray_request(op,**fields):
     driver.stdin.write(json.dumps(dict(op=op,**fields))+'\n');driver.stdin.flush();reply=json.loads(driver.stdout.readline());assert reply['ok'],reply;return reply['value']
    item=next(item for item in tray_request('tray') if item.get('Id')=='dome-identities');assert item['managed'] and item['movable']
    tray_request('placement',item=item,managed=False)
    assert not next(item for item in tray_request('tray') if item.get('Id')=='dome-identities')['managed']
    tray_request('placement',item=item,managed=True)
    assert next(item for item in tray_request('tray') if item.get('Id')=='dome-identities')['managed']
   finally:driver.stdin.close();assert driver.wait(timeout=5)==0
  assert key.read_bytes()==original
  command('Quit');assert app.wait(timeout=5)==0
  print('PASS native FLTK window, shared fixture listing, universal commands, tray registration/pixmap, close-to-tray, activation, DomeD default placement/overrides and clean quit without changing keys')
 finally:
  if app.poll() is None:app.terminate();app.wait(timeout=5)
  watcher.terminate();watcher.wait(timeout=5);xd.close();xvfb.terminate();xvfb.wait(timeout=5);log.close()
