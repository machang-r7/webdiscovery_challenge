async function getHash(blob, algo = "SHA-256") {
  // convert your Blob to an ArrayBuffer
  // could also use a FileRedaer for this for browsers that don't support Response API
  const buf = await new Response(blob).arrayBuffer();
  const hash = await crypto.subtle.digest(algo, buf);
  let result = '';
  const view = new DataView(hash);
  for (let i = 0; i < hash.byteLength; i += 4) {
     result += view.getUint32(i).toString(16).padStart(2, '0');
  }
  return result;
}
inp.onchange = e => {
  getHash(inp.files[0]).then(console.log);
};
 //const url = "/login-dev"
const form = document.getElementById('login-form');
  const username = document.getElementById('username');
  const password = document.getElementById('password');

  form.addEventListener('submit', function(event) {
    event.preventDefault();

    const validCredentials = [
      { username: 'user1', password: 'pass1' },
      { username: 'user2', password: 'pass2' }
    ];

    for (const credential of validCredentials) {
      if (credential.username === username.value && credential.password === password.value) {
        window.location.href = '/home';
      } else {
        alert('Invalid username or password');
      }
    }
  });

  const form = document.getElementById('signup-form');
  const username = document.getElementById('username');
  const password = document.getElementById('password');
  

  form.addEventListener('submit', function(event) {
    event.preventDefault();

    const validCredentials = [
      { username: 'user1', password: 'pass1' },
      { username: 'user2', password: 'pass2' }
    ];

    for (const credential of validCredentials) {
      if (credential.username === username.value && credential.password === password.value) {
        window.location.href = '/home';
      } else {
        alert('weeee');
      }
    }
  });
$.ajax({ 
   type : "GET", 
   url : "/debugfortesting", 
   beforeSend: function(xhr){xhr.setRequestHeader('X-ISDEV', 'true');},
   success : function(result) { 
       //todo 
   }, 
   error : function(result) { 
     //handle the error 
   } 
 }); 
