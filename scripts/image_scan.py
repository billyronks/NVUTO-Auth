"""Scan the exact app and pinned supporting images. Requires Trivy on PATH."""
import json,pathlib,re,subprocess,uuid
root=pathlib.Path(__file__).resolve().parents[1]
run=root/'.local'/('image-scan-'+uuid.uuid4().hex);run.mkdir(parents=True)
ignore=run/'no-exemptions.ignore';ignore.write_text('')
images={'application':'nvuto-auth:acceptance'}
for name,file in [('database','compose.yaml'),('https_proxy','compose.production.yaml')]:
 images[name]=re.search(r'^\s+image:\s+(\S+)',(root/file).read_text(),re.M)[1]
summary={};failed=False
for name,image in images.items():
 path=run/(name+'.json')
 subprocess.run(['trivy','image','--scanners','vuln','--ignorefile',str(ignore),'--ignore-unfixed=false','--severity','UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL','--format','json','--output',str(path),image],check=True,cwd=root)
 report=json.loads(path.read_text())
 findings=[{'id':v['VulnerabilityID'],'package':v['PkgName'],'installed':v['InstalledVersion'],'fixed':v.get('FixedVersion',''),'severity':v['Severity']} for result in report.get('Results',[]) for v in result.get('Vulnerabilities',[])]
 serious=[v for v in findings if v['severity'] in ['HIGH','CRITICAL']]
 summary[name]={'image':image,'artifact_id':report.get('Metadata',{}).get('ImageID'),'findings':findings,'high_critical':len(serious)}
 failed|=bool(serious)
(run/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2));print('Evidence:',run)
if failed:raise SystemExit('High/critical image findings require remediation or a specific documented review.')
