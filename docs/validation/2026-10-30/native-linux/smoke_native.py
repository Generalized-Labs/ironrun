import json,os,subprocess,time
from pathlib import Path
out=Path(__file__).resolve().parent
root=Path('/workspace/ironrun-product-tools/native-linux/extracted')
with (out/'daemon.stdout.log').open('wb')as stdout,(out/'daemon.stderr.log').open('wb')as stderr:
 p=subprocess.Popen([str(root/'usr/bin/gnome-keyring-daemon'),'--foreground','--components=secrets','--control-directory',str(out/'smoke-home/runtime/keyring'),'--unlock'],stdin=subprocess.PIPE,stdout=stdout,stderr=stderr)
 try:
  p.stdin.write(b'ironrun-synthetic-isolated-collection-password\n');p.stdin.close()
  owned=False
  for _ in range(50):
   q=subprocess.run(['gdbus','call','--session','--dest','org.freedesktop.DBus','--object-path','/org/freedesktop/DBus','--method','org.freedesktop.DBus.NameHasOwner','org.freedesktop.secrets'],capture_output=True,text=True,timeout=2)
   if '(true,)'in q.stdout:owned=True;break
   if p.poll()is not None:break
   time.sleep(.1)
  assert owned, 'Secret Service did not register; daemon exit='+str(p.poll())
  tool=str(root/'usr/bin/secret-tool')
  q=subprocess.run([tool,'store','--label=Ironrun synthetic native fixture','fixture','ironrun-native-readiness'],input=b'synthetic-native-marker\n',capture_output=True,timeout=10)
  assert q.returncode==0,q.stderr.decode()
  q=subprocess.run([tool,'lookup','fixture','ironrun-native-readiness'],capture_output=True,timeout=10)
  assert q.returncode==0 and q.stdout.strip()==b'synthetic-native-marker'
  q=subprocess.run([tool,'clear','fixture','ironrun-native-readiness'],capture_output=True,timeout=10);assert q.returncode==0
  print(json.dumps({'secret_service_registered':True,'actual_store_lookup_clear':'passed','backend':'gnome-keyring48.0 + libsecret secret-tool0.21.7','existing_stores_accessed':False}))
 finally:
  p.terminate()
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:p.kill();p.wait()
