"""Called only by integration.py against its fresh private database and live auth binary."""
import base64,hashlib,hmac,json,os,pathlib,secrets,socket,struct,subprocess,time,urllib.error,urllib.request

def run(root,env,pg,port,command,evidence_directory):
 if env.get('AUTH_ISOLATED_TEST')!='1':raise RuntimeError('Fresh integration database required')
 auth=env['PUBLIC_URL'];email='product-example@example.test';password=secrets.token_urlsafe(24)
 def request(base,path,body=None,bearer='',want=200):
  req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':base,**({'Authorization':'Bearer '+bearer} if bearer else {})})
  try:response=urllib.request.urlopen(req,timeout=10)
  except urllib.error.HTTPError as error:response=error
  with response:
   raw=response.read();assert response.status==want,(path,response.status)
   return json.loads(raw) if response.status==200 else None
 request(auth,'/api/v1/auth/register',{'tenant':'workspace','email':email,'password':password,'name':'Example product user'})
 # Test fixture only: delivery/verification is separately tested by the auth suite.
 # No verification bypass exists in the application or example.
 psql=[pg/('psql.exe' if os.name=='nt' else 'psql'),'-h','127.0.0.1','-p',port,'-U','nvuto_test','-d','auth_acceptance','-v','ON_ERROR_STOP=1']
 command(psql+['-c',"UPDATE auth_users SET verified=true WHERE email='product-example@example.test' AND tenant_id=(SELECT id FROM auth_tenants WHERE slug='workspace')"],env=env,stdout=subprocess.DEVNULL)
 tenant=subprocess.check_output([str(x) for x in psql+['-At','-c',"SELECT id FROM auth_tenants WHERE slug='workspace'"]],env=env,text=True).strip()
 binary=root/'.cache/product-app.exe'
 command(['go','build','-o',binary,'./examples/product-app'],cwd=root,env=env)
 with socket.socket() as sock:sock.bind(('127.0.0.1',0));app_port=sock.getsockname()[1]
 app=f'http://127.0.0.1:{app_port}';settings=dict(env,AUTH_URL=auth,APP_PUBLIC_URL=app,APP_LISTEN_ADDR=f'127.0.0.1:{app_port}',EXPECTED_TENANT_ID=tenant)
 process=subprocess.Popen([str(binary)],cwd=root,env=settings,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 try:
  for attempt in range(100):
   if process.poll() is not None:raise RuntimeError('Example failed to start')
   try:request(app,'/api/config');break
   except OSError:time.sleep(0.1)
  else:raise RuntimeError('Example readiness timed out')
  request(app,'/api/projects',want=401)
  session=request(app,'/api/auth/login',{'tenant':'workspace','email':email,'password':password})['data']
  projects=request(app,'/api/projects',bearer=session['access_token'])
  assert projects['tenant_id']==tenant and projects['projects'][0]['owner_id']==projects['user_id']
  proof=request(auth,'/api/v1/auth/step-up',{'password':password},session['access_token'])['data']['proof']
  pending=request(auth,'/api/v1/auth/mfa/setup',{'proof':proof},session['access_token'])['data']
  secret=pending['secret'];key=base64.b32decode(secret+'='*((-len(secret))%8))
  digest=hmac.new(key,struct.pack('>Q',int(time.time())//30),hashlib.sha1).digest();offset=digest[-1]&15
  code=str((struct.unpack('>I',digest[offset:offset+4])[0]&0x7fffffff)%1000000).zfill(6)
  recovery=request(auth,'/api/v1/auth/mfa/confirm',{'token':pending['enrollment_token'],'code':code},session['access_token'])['data']['recovery_codes'][0]
  request(app,'/api/projects',bearer=session['access_token'],want=401)
  challenge=request(app,'/api/auth/login',{'tenant':'workspace','email':email,'password':password})['data']
  assert challenge['mfa_required'] is True
  session=request(app,'/api/auth/mfa/verify',{'token':challenge['challenge'],'recovery_code':recovery})['data']
  request(app,'/api/projects',bearer=session['access_token'])
  old=session['access_token'];session=request(app,'/api/auth/refresh',{'refresh_token':session['refresh_token']})['data']
  request(app,'/api/projects',bearer=old,want=401)
  request(app,'/api/projects',bearer=session['access_token'])
  request(app,'/api/auth/logout',{'refresh_token':session['refresh_token']},session['access_token'])
  request(app,'/api/projects',bearer=session['access_token'],want=401)
  (evidence_directory/'product-example.json').write_text(json.dumps({'result':'passed','scope':'fresh private PostgreSQL and actual auth/product binaries','checks':['login','workspace and owner scoping','TOTP enrollment and old-session revocation','MFA recovery challenge through product adapter','refresh rotation','logout and immediate revocation'],'real_provider_email':False},indent=2)+'\n')
  print('Product example against real auth: login, workspace/owner scope, MFA/recovery, refresh rotation, logout and immediate revocation passed.',flush=True)
 finally:process.terminate();process.wait(timeout=10)
