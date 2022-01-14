if (!window.PublicKeyCredential) {
  document.getElementById('webauthn-not-defined-error').style.display = 'block'
}

function handleStatus(content) {
  document.getElementById('u2f-status').textContent = content
}

function ab2str(buf) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))).replace(/\//g, '_').replace(/\+/g, '-').replace(/=*$/, '');
}
function str2ab(enc) {
  let str = atob(enc.replace(/_/g, '/').replace(/-/g, '+'));
  let buf = new ArrayBuffer(str.length);
  let bufView = new Uint8Array(buf);
  for (let i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
function processCredentials(credentials) {
  // modifies the object
  // converts specific fields to ArrayBuffers of Uint8Array
  credentials.publicKey.challenge = str2ab(credentials.publicKey.challenge)
  for (let i=0; i<credentials.publicKey.allowCredentials.length; i++) {
    credentials.publicKey.allowCredentials[i].id = str2ab(credentials.publicKey.allowCredentials[i].id)
  }
}

function processRegistrationOptions(opt) {
  // modifies the object
  // converts specific fields to ArrayBuffers of Uint8Array
  opt.challenge = str2ab(opt.challenge)
  for (let i=0; i<opt.excludeCredentials.length; i++) {
    opt.excludeCredentials[i].id = str2ab(opt.excludeCredentials[i].id)
  }
  opt.user.id = str2ab(opt.user.id)
}

async function get_credentials() {
  let cred = JSON.parse(document.getElementById('django_u2f_request').innerHTML);
  processCredentials(cred)
  const resp = await navigator.credentials.get(cred)
    .catch(function() {handleStatus('Authorization Failed')})
  if (resp === undefined) {
    handleStatus('Authorization Failed')
    return
  }
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

async function do_registration() {
  let opt = JSON.parse(document.getElementById('django_u2f_registration').innerHTML)
  processRegistrationOptions(opt)
  let resp
  try {
    resp = await navigator.credentials.create({publicKey: opt})
  } catch(error) {
    if (error.message.indexOf('attempt was made to use an object that is not') >= 0) {
      handleStatus('Registration Failed: Key may have already been registered.')
    }
    return
  }
  if (resp === undefined) {
    handleStatus('Registration failed.')
    return
  }
  const respObject = {
    id: resp.id,
    rawId: ab2str(resp.rawId),
    response: {
      attestationObject: ab2str(resp.response.attestationObject),
      clientDataJSON: ab2str(resp.response.clientDataJSON),
    },
    type: resp.type,
    clientExtensionResults: resp.getClientExtensionResults(),
  }
  const form = document.getElementById('u2f-form')
  form.response.value = JSON.stringify(respObject)
  form.submit()
}

const requestElem = document.getElementById('django_u2f_request')
if (requestElem) {
  get_credentials()
}

const registrationElem = document.getElementById('django_u2f_registration')
if (registrationElem) {
  do_registration()
}
