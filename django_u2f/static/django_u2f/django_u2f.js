if (typeof window.u2f === 'undefined')
  document.getElementById('u2f-not-defined-error').style.display = 'block';

function ab2str(buf) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))).replace(/\//g, '_').replace(/\+/g, '-').replace(/=*$/, '');
}
function str2ab(enc) {
  var str = atob(enc.replace(/_/g, '/').replace(/-/g, '+'));
  var buf = new ArrayBuffer(str.length);
  var bufView = new Uint8Array(buf);
  for (var i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
function processCredentials(credentials) {
  // modifies the object
  // converts specific fields to ArrayBuffers of Uint8Array
  credentials.publicKey.challenge = str2ab(credentials.publicKey.challenge)
  for (var i=0; i<credentials.publicKey.allowCredentials.length; i++) {
    credentials.publicKey.allowCredentials[i].id = str2ab(credentials.publicKey.allowCredentials[i].id)
  }
}

async function get_credentials() {
  let cred = JSON.parse(document.getElementById('django_u2f_request').innerHTML);
  processCredentials(cred);
  const resp = await navigator.credentials.get(cred)
  const respObject = {
    id: resp.id,
    rawId: ab2str(resp.rawId),
    response: {
      authenticatorData: ab2str(resp.response.authenticatorData),
      clientDataJSON: ab2str(resp.response.clientDataJSON),
      signature: ab2str(resp.response.signature),
      userHandle: resp.response.userHandle,
    },
    type: resp.type,
    clientExtensionResults: resp.getClientExtensionResults(),
  }
  const form = document.getElementById('u2f-form')
  form.response.value = JSON.stringify(respObject)
  form.submit()
}
get_credentials()
