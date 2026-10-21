import json,pathlib
root=pathlib.Path(__file__).resolve().parents[1]
string={'type':'string'}
fields={name:dict(string) for name in ['tenant','email','name','password','new_password','code','recovery_code','token','refresh_token','proof','user_id','state']}
for key in ['token','refresh_token','proof','recovery_code']:fields[key].update(minLength=43,maxLength=43)
fields['tenant']['pattern']='^[a-z0-9][a-z0-9-]{1,62}$'
fields['email'].update(format='email',maxLength=254)
fields['name']['maxLength']=120
fields['state']['enum']=['active','disabled']
fields['code']['pattern']='^[0-9]{6}$'
fields['user_id']['format']='uuid'
for key in ['password','new_password']:fields[key].update(minLength=15,maxLength=72,format='password',description='At least 15 Unicode characters; at most 72 UTF-8 bytes.')
def obj(properties,required=None):return {'type':'object','properties':properties,'required':list(properties) if required is None else required,'additionalProperties':False}
def ref(name):return {'$ref':'#/components/schemas/'+name}
schemas={}
schemas['Error']=obj({'error':string})
schemas['Identity']=obj({'id':{'type':'string','format':'uuid'},'tenant_id':{'type':'string','format':'uuid'},'email':fields['email'],'name':string,'role':{'type':'string','enum':['owner','member']},'mfa_enabled':{'type':'boolean'}})
schemas['Message']=obj({'message':string})
schemas['Session']=obj({'access_token':fields['token'],'refresh_token':fields['token'],'token_type':{'const':'Bearer'},'expires_in':{'type':'integer','maximum':900},'session_id':{'type':'string','format':'uuid'},'mfa_enrollment_required':{'type':'boolean','description':'Only step-up, MFA enrollment/confirmation and logout are permitted until enrollment finishes.'},'user':ref('Identity')})
schemas['Challenge']=obj({'mfa_required':{'const':True},'challenge':fields['token'],'expires_in':{'const':300}})
schemas['Login']={'oneOf':[ref('Session'),ref('Challenge')]}
schemas['Proof']=obj({'proof':fields['proof'],'expires_in':{'const':300}})
schemas['Enrollment']=obj({'secret':string,'otpauth_url':string,'enrollment_token':fields['token'],'expires_in':{'const':600}})
schemas['Recovery']=obj({'recovery_codes':{'type':'array','minItems':10,'maxItems':10,'items':fields['recovery_code']},'message':string})
schemas['Invitation']=obj({'user_id':fields['user_id']})
schemas['Changed']={'oneOf':[obj({'changed':{'type':'boolean'}}),obj({'revoked':{'type':'boolean'}})]}
schemas['SessionList']={'type':'array','items':obj({'id':{'type':'string','format':'uuid'},'created_at':{'type':'string','format':'date-time'},'expires_at':{'type':'string','format':'date-time'},'current':{'type':'boolean'}})}
specs=[
('post','register','Register a member','tenant email password','name','Message',False),
('post','verify-email','Consume email verification','token','','Message',False),
('post','resend-verification','Queue another verification email','tenant email','','Message',False),
('post','login','Sign in or receive an MFA challenge','tenant email password','','Login',False),
('post','mfa/verify','Consume a challenge; provide code OR recovery_code','token','code recovery_code','Session',False),
('post','refresh','Rotate refresh; reuse revokes the entire session family','refresh_token','','Session',False),
('get','me','Resolve current authorized identity','','','Identity',True),
('post','logout','Revoke using a valid bearer or its stored refresh_token','','refresh_token','Changed',False),
('post','forgot-password','Queue password recovery','tenant email','','Message',False),
('post','reset-password','Change password and return to sign-in','token new_password','','Message',False),
('post','step-up','Prove password and enrolled MFA','password','code recovery_code','Proof',True),
('post','change-password','Change password with session-bound proof','proof new_password','','Message',True),
('post','mfa/setup','Start separate pending TOTP enrollment','proof','','Enrollment',True),
('post','mfa/confirm','Confirm enrollment and revoke prior credentials','token code','','Recovery',True),
('post','mfa/disable','Disable MFA with fresh proof','proof','','Message',True),
('get','sessions','List live sessions','','','SessionList',True),
('delete','sessions/{id}','Revoke an owned session','','','Changed',True),
('post','sessions/revoke-others','Revoke other sessions','','','Changed',True),
('post','invitations','Owner invites an unprivileged member','email proof','name','Invitation',True),
('post','invitations/{id}/resend','Replace a pending invitation','proof','','Changed',True),
('delete','invitations/{id}','Revoke a pending invitation','proof','','Changed',True),
('post','invitations/accept','Consume invitation and set initial password','token new_password','','Message',False),
('post','admin/mfa-reset','Owner resets another member factor; re-enrollment required','user_id proof','','Changed',True),
('post','admin/user-state','Owner enables/disables another member','user_id state proof','','Changed',True)]
paths={}
for method,path,summary,required,optional,response,protected in specs:
 operation={'summary':summary,'operationId':method+'_'+path.replace('/','_').replace('{','').replace('}','').replace('-','_'),'security':[{'bearerAuth':[]}] if protected else [],'responses':{}}
 for status,description in [(200,'Success; emails are durably queued, not guaranteed inbox delivery.'),(400,'Invalid request or password policy.'),(401,'Invalid, expired, consumed or revoked credential.'),(403,'Origin, privilege, registration mode or enrollment restriction.'),(429,'Rate limit exceeded.'),(503,'Database, limiter or persistence unavailable.')]:
  schema=obj({'data':ref(response)}) if status==200 else ref('Error')
  operation['responses'][str(status)]={'description':description,'content':{'application/json':{'schema':schema}}}
 required=required.split();optional=optional.split()
 if required or optional:operation['requestBody']={'required':bool(required),'content':{'application/json':{'schema':obj({key:fields[key] for key in required+optional},required)}}}
 if '{id}' in path:operation['parameters']=[{'name':'id','in':'path','required':True,'schema':{'type':'string','format':'uuid'}}]
 paths.setdefault('/api/v1/auth/'+path,{})[method]=operation
for path in ['/health','/ready']:paths[path]={'get':{'summary':'Process liveness' if path=='/health' else 'Database/schema and sustained mail queue readiness','responses':{'200':{'description':'Healthy'},'503':{'description':'Not ready'}}}}
contract={'openapi':'3.1.0','info':{'title':'NVUTO Auth','version':'0.1.0','description':'Standalone bearer-only service. No cookies, JWTs, OIDC/OAuth. 16 KiB request maximum; documented database-coordinated rate limits. See docs/OPERATIONS.md.'},'servers':[{'url':'/'}],'paths':paths,'components':{'securitySchemes':{'bearerAuth':{'type':'http','scheme':'bearer','bearerFormat':'opaque 256-bit reference token'}},'schemas':schemas}}
(root/'openapi.json').write_text(json.dumps(contract,indent=2)+'\n',encoding='utf-8',newline='\n')
