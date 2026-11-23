"""Genera un visor de resultados reales; no simula una interfaz del chat."""
import hashlib
import html
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import xml.etree.ElementTree as ET

root=Path(__file__).resolve().parents[2]
folder=root/'evidence/seguridad'
raw=(folder/'https-results.json').read_bytes()
data=json.loads(raw)
digest=hashlib.sha256(raw).hexdigest()
date=datetime.fromisoformat(data['executed_at']).astimezone(timezone(timedelta(hours=-5))).strftime('%d/%m/%Y %H:%M:%S UTC-5')
groups=[('01-autenticacion','Autenticación y creación de usuario',['E-01','E-02','E-03','E-06']),
        ('02-autorizacion','Acceso permitido y acceso denegado',['E-04','E-05','E-08','E-09']),
        ('03-proteccion','Protección de credenciales, auditoría y TLS',['E-07','E-11','E-12']),
        ('04-sesiones','Revocación y caducidad de sesiones',['E-10','E-13','E-14'])]
style='''body{font:18px Arial,sans-serif;color:#182129;background:#eef1f4;margin:0;padding:32px}main{max-width:1050px;margin:auto}header{background:white;border-top:7px solid #8d0c41;padding:24px 28px;margin-bottom:20px}h1{font-size:29px;margin:10px 0}h2{font-size:21px;margin:0}p{line-height:1.45;margin:8px 0}.label{color:#8d0c41;font-weight:bold;font-size:15px;letter-spacing:1px}.meta{font-size:15px;color:#465363}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}article{background:white;border:1px solid #cbd2d9;padding:21px;break-inside:avoid}.status{color:#13633b;font-weight:bold;float:right}.codes{font-size:14px;color:#465363;margin:9px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:16px/1.5 Consolas,monospace;background:#f3f5f7;padding:14px;margin-bottom:0}.foot{background:white;margin-top:18px;padding:18px;font-size:14px;line-height:1.5}.block{display:block}strong{font-weight:700}'''
def page(title,content,origin='https-results.json',checksum=digest):
    return '<!doctype html><html lang="es"><meta charset="utf-8"><title>'+html.escape(title)+'</title><style>'+style+'</style><main><header><div class="label">UIDE · FUNDAMENTOS DE SEGURIDAD · FASE 3</div><h1>'+html.escape(title)+'</h1><p>Visor de evidencias ejecutadas · Captura de resultados reales</p><p class="meta">'+html.escape(date)+' · HTTPS de loopback · SQLite temporal de laboratorio</p></header>'+content+'<div class="foot"><b>Origen:</b> '+html.escape(origin)+'<br>SHA-256 del origen: '+checksum+'<br>Respuestas sanitizadas: no se muestran contraseñas, tokens ni claves privadas.<br>Este visor presenta resultados de pruebas; no es la interfaz del chat ni acredita despliegue entre sedes.</div></main></html>'
for name,title,ids in groups:
    cards=[]
    for r in data['results']:
        if r['id'] not in ids:continue
        assert r['passed']
        info=r['evidence'].copy() if isinstance(r['evidence'],dict) else r['evidence']
        if r['id']=='E-11':info={'event_count':info['event_count'],'secrets_found':info['secrets_found'],'sample':info['sample'][:1]}
        expected=json.dumps(r['expected']);actual=json.dumps(r['obtained'])
        cards.append('<article><span class="status">APROBADA</span><h2>'+r['id']+'</h2><p>'+html.escape(r['action'])+'</p><div class="codes">'+r['requirement']+' · '+r['control']+'</div><p><b>Esperado:</b> '+expected+' &nbsp; <b>Obtenido:</b> '+actual+'</p><pre>'+html.escape(json.dumps(info,ensure_ascii=False,indent=2))+'</pre></article>')
    (folder/(name+'.html')).write_text(page(title,'<section class="grid">'+''.join(cards)+'</section>'),encoding='utf-8')
suite=ET.parse(folder/'pytest-results.xml').getroot().find('testsuite')
events=[json.loads(line) for line in (folder/'go-tests.jsonl').read_text().splitlines() if line.startswith('{')]
passed=[e['Test'] for e in events if e.get('Action')=='pass' and e.get('Test')]
console=(folder/'pytest-console.txt').read_text(encoding='utf-8')
content='<section class="grid"><article><h2>FastAPI · pytest</h2><p class="status">'+suite.get('tests')+' PRUEBAS APROBADAS</p><p>Fallos: '+suite.get('failures')+' · Errores: '+suite.get('errors')+'</p><pre>'+html.escape(console)+'</pre></article><article><h2>Adaptador Go · go test</h2><p class="status">'+str(len(passed))+' PRUEBAS APROBADAS</p><pre>'+html.escape('\n'.join('PASS '+v for v in passed))+'</pre><p>Suite: '+str(next(e['Elapsed'] for e in events if e.get('Action')=='pass' and not e.get('Test'))) +' s.</p></article></section>'
sources=['pytest-results.xml','pytest-console.txt','go-tests.jsonl']
combined=hashlib.sha256(b''.join((folder/name).read_bytes() for name in sources)).hexdigest()
(folder/'05-pruebas.html').write_text(page('Resultados de las pruebas automatizadas',content,' + '.join(sources),combined),encoding='utf-8')
print('Generados 5 visores desde JSON, XML y salida real de pruebas. Sin datos de entrada secretos.')
