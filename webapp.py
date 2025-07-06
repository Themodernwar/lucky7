from flask import Flask, request, render_template_string
from datetime import datetime
import json
import db
import reputation
import config

app = Flask(__name__)

INDEX_HTML = """
<!doctype html>
<html>
<head>
    <title>Welcome</title>
    <script src='/fp.js'></script>
</head>
<body>
<h1>Lucky7 Training Server</h1>
</body>
</html>
"""

FINGERPRINT_JS = """
(async function(){
    async function sha256(str){
        const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
        return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
    }
    function canvasHash(){
        try{
            var c=document.createElement('canvas');
            var ctx=c.getContext('2d');
            ctx.textBaseline='top';
            ctx.font='14px Arial';
            ctx.fillText('Lucky7',2,2);
            return sha256(c.toDataURL());
        }catch(e){return 'nocanvas';}
    }
    function webglHash(){
        var canvas=document.createElement('canvas');
        var gl=canvas.getContext('webgl')||canvas.getContext('experimental-webgl');
        if(!gl) return 'nowebgl';
        var debug=gl.getExtension('WEBGL_debug_renderer_info');
        var vendor=debug?gl.getParameter(debug.UNMASKED_VENDOR_WEBGL):'';
        var renderer=debug?gl.getParameter(debug.UNMASKED_RENDERER_WEBGL):'';
        return sha256(vendor+renderer);
    }
    const ua=navigator.userAgent;
    const scr=screen.width+'x'+screen.height;
    const tz=(Intl.DateTimeFormat().resolvedOptions().timeZone||'unknown');
    const platform=navigator.platform;
    const wh=await webglHash();
    const ch=await canvasHash();
    const fp=await sha256(ua+'|'+scr+'|'+tz+'|'+platform+'|'+wh+'|'+ch);
    const payload={
        user_agent:ua,
        screen:scr,
        timezone:tz,
        platform:platform,
        webgl_hash:wh,
        canvas_hash:ch,
        fp_hash:fp
    };
    fetch('/collect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
})();
"""

@app.route('/')
def index():
    return INDEX_HTML

@app.route('/fp.js')
def fp_js():
    return FINGERPRINT_JS, 200, {'Content-Type':'application/javascript'}

@app.route('/collect', methods=['POST'])
def collect():
    data = request.get_json() or {}
    data['timestamp'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    data['ip'] = request.remote_addr
    db.insert_fingerprint(data)
    return 'ok'

LOGIN_HTML = """
<form method='POST'>
    <input name='username' placeholder='Username'>
    <input type='password' name='password' placeholder='Password'>
    <input type='submit' value='Login'>
</form>
"""

@app.route('/honeypot/login', methods=['GET','POST'])
def honeypot_login():
    if request.method == 'POST':
        db.insert_honeypot_event({
            'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'ip': request.remote_addr,
            'endpoint': '/honeypot/login',
            'method': 'POST',
            'headers': json.dumps(dict(request.headers)),
            'data': json.dumps(request.form.to_dict())
        })
        return 'Invalid credentials', 401
    return LOGIN_HTML

@app.route('/download/fake')
def fake_download():
    db.insert_honeypot_event({
        'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        'ip': request.remote_addr,
        'endpoint': '/download/fake',
        'method': 'GET',
        'headers': json.dumps(dict(request.headers)),
        'data': ''
    })
    return 'File not available', 404


BAD_ASN_KEYWORDS = ["amazon", "digitalocean", "ovh", "google", "microsoft", "cloud"]


def score_client(ip: str) -> int:
    """Calculate a simple risk score for an IP."""
    fp_total = db.count_fingerprints(ip)
    hp = db.count_honeypot_events(ip)
    unique = 0
    for fp_hash in db.get_fingerprint_hashes(ip):
        if db.count_fingerprint_hash(fp_hash) == 1:
            unique += 1

    score = fp_total * 5 + hp * 20 + unique * 3

    info = reputation._ipinfo_lookup(
        ip, config.load_config().get("reputation", {}).get("ipinfo_token", "")
    )
    if info:
        asn = info.get("org", "").lower()
        if any(k in asn for k in BAD_ASN_KEYWORDS):
            score += 20

    return score

@app.route('/score')
def score_endpoint():
    ip = request.args.get('ip', request.remote_addr)
    score = score_client(ip)
    return {'ip': ip, 'score': score}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
