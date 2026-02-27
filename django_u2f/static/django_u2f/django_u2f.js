if (!window.PublicKeyCredential) {
  document.getElementById('webauthn-not-defined-error').style.display = 'block'
}

function handleStatus(content) {
  const el = document.getElementById('u2f-status');
  if (el) {
    el.textContent = content;
  } else {
    console.error(content);
  }
}

async function get_credentials_value(cred) {
  const options = PublicKeyCredential.parseRequestOptionsFromJSON(cred.publicKey)
  const resp = await navigator.credentials.get({ publicKey: options })
  return resp.toJSON()
}

async function get_credentials() {
  const cred = JSON.parse(document.getElementById('django_u2f_request').innerHTML)
  try {
    const respObject = await get_credentials_value(cred)
    const form = document.getElementById('u2f-form')
    form.response.value = JSON.stringify(respObject)
    form.submit()
  } catch (error) {
    handleStatus('Authorization Failed: ' + error.message)
  }
}

async function do_registration_value(opt) {
  const options = PublicKeyCredential.parseCreationOptionsFromJSON(opt)
  const resp = await navigator.credentials.create({ publicKey: options })
  return resp.toJSON()
}

async function do_registration() {
  const opt = JSON.parse(document.getElementById('django_u2f_registration').innerHTML)
  try {
    const respObject = await do_registration_value(opt)
    const form = document.getElementById('u2f-form')
    form.response.value = JSON.stringify(respObject)
    form.submit()
  } catch (error) {
    handleStatus('Registration Failed: ' + error.message)
  }
}

const requestElem = document.getElementById('django_u2f_request')
if (requestElem) {
  get_credentials()
}

const registrationElem = document.getElementById('django_u2f_registration')
if (registrationElem) {
  do_registration()
}
