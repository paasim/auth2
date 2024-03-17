/** @param {string} jwt */
function jwtPayload(jwt) {
  return JSON.parse(atob(jwt.split('.')[1]))
}

/** @param {string} str */
function urlsafeB64Decode(str) {
  return Uint8Array.from(atob(str.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0))
}

/** @param {ArrayBuffer} arr */
function urlsafeB64Encode(arr) {
  return btoa(String.fromCharCode(...new Uint8Array(arr)));
}

/** generate webauthn credentials, save results to registration-form fields */
async function genCreds() {
  const form = document.getElementById('registration-form');

  if (!form.name.checkValidity()) {
    form.name.reportValidity();
    return
  }
  form.name.readOnly = true;


  const jwt_pl = jwtPayload(form.session_token.value);
  const rp = { id: jwt_pl.iss, name: jwt_pl.aud };
  const user = {
    id: urlsafeB64Decode(jwt_pl.sub),
    name: form.name.value,
    displayName: form.name.value
  };
  const publicKey = {
    attestation: 'none',
    authenticatorSelection: { userVerification: 'required' },
    challenge: urlsafeB64Decode(jwt_pl.challenge),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    rp,
    user
  };

  const creds = await navigator.credentials.create({ publicKey });
  form.raw_id.value = urlsafeB64Encode(creds.rawId);
  form.typ.value = creds.type;
  form.authenticator_response.value = urlsafeB64Encode(creds.response.attestationObject);
  form.client_data_json.value = urlsafeB64Encode(creds.response.clientDataJSON);

  document.getElementById('registration-button').disabled = false;
  document.getElementById('gen-creds').disabled = true;
}

/** get webauthn credentials, save results to authentication-form fields */
async function getCreds() {
  const form = document.getElementById('authentication-form');

  if (!form.name.checkValidity()) {
    form.name.reportValidity();
    return
  }

  const name_query = new URLSearchParams({ name: form.name.value });
  const auth_data = await fetch(`/webauthn/auth_data?${name_query}`).then(r => r.json());
  if (auth_data.ids.length === 0) {
    // FIXME: report no creds
    return
  }
  const allowCredentials = auth_data.ids.map(id => ({
    id: urlsafeB64Decode(id),
    type: "public-key",
  }));
  form.name.readOnly = true;

  form.session_token.value = auth_data.session_token
  const jwt_pl = jwtPayload(auth_data.session_token);
  const publicKey = {
    allowCredentials,
    challenge: urlsafeB64Decode(jwt_pl.challenge),
    rpId: jwt_pl.iss,
    userVerification: "required"
  };
  const creds = await navigator.credentials.get({ publicKey });

  form.raw_id.value = urlsafeB64Encode(creds.rawId);
  form.typ.value = creds.type;
  form.authenticator_response.value = urlsafeB64Encode(creds.response.authenticatorData);
  form.authenticator_response.value += '.'
  form.authenticator_response.value += urlsafeB64Encode(creds.response.signature);
  form.client_data_json.value = urlsafeB64Encode(creds.response.clientDataJSON);

  document.getElementById('authentication-button').disabled = false;
  document.getElementById('get-creds').disabled = true;
}
