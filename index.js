const https = require('https');
const fs = require('fs');
const acme = require('acme-client');
const { Route53 } = require('aws-sdk');
const passwordHash = require('password-hash');

const route53 = new Route53();
let db = { ssl: {}};
try {
  db = JSON.parse(fs.readFileSync('./settings.json'));
} catch (e) {}

const restrictedNames = [
  "www", "www2", "owen", "certification",
  "mail", "remote", "webmail", "ns1", "ns2", "smtp",
  "server", "secure", "vpn", "api", "official",
  "email", "shop", "ftp", "test", "ns", "portal", "support",
  "dev", "web", "mx", "admin", "cloud", "forum"
];


function save() {
  fs.writeFileSync('./settings.json', JSON.stringify(db));
}

function createRecord(subdomain, ip, keyAuthorization) {
  var params = {
    ChangeBatch: {
      Changes: [
        {
          Action: "UPSERT",
          ResourceRecordSet: {
            Name: `${subdomain}.theremote.io`,
            ResourceRecords: [
              {
                Value: ip
              }
            ],
            TTL: 60,
            Type: "A"
          }
        },
        {
          Action: "UPSERT",
          ResourceRecordSet: {
            Name: `_acme-challenge.${subdomain}.theremote.io`,
            ResourceRecords: [
              {
                Value: `"${keyAuthorization}"`
              }
            ],
            TTL: 30,
            Type: "TXT"
          }
        }
      ],
      Comment: "cert for RMS"
    },
    HostedZoneId: "Z3OXPV1SZLXM0K"
  };
  return new Promise((resolve) => {
    route53.changeResourceRecordSets(params, (err, dat) => {
      resolve();
    });
  });
}

async function setupCerts() {
  if (!! db.ssl.expire || db.ssl.expire < new Date().getTime()) {
    return;
  }

  const client = new acme.Client({
    directoryUrl: acme.directory.letsencrypt.production,
    accountKey: await acme.forge.createPrivateKey()
  });

  try {
    client.getAccountUrl();
  } catch (e) {
    await client.createAccount({
      termsOfServiceAgreed: true,
      contact: ['mailto:hardy.owen+test@gmail.com'],
    });
  }

  /* Place new order */
  const order = await client.createOrder({
    identifiers: [
      {type: 'dns', value: 'certification.theremote.io'},
    ],
  });

  /* Get authorizations and select challenges */
  const [authz] = await client.getAuthorizations(order);

  const challenge = authz.challenges.find(o => o.type === 'dns-01');
  const keyAuthorization = await client.getChallengeKeyAuthorization(challenge);

  await createRecord('certification', '173.212.229.220', keyAuthorization);

  console.log(keyAuthorization);

  try {
    await client.verifyChallenge(authz, challenge);
  } catch (e) {
    console.log('could not verify, trying anyway');
  }

  /* Notify ACME provider that challenge is satisfied */
  await client.completeChallenge(challenge);

  /* Wait for ACME provider to respond with valid status */
  await client.waitForValidStatus(challenge);
  console.log('done');


  const [key, csr] = await acme.forge.createCsr({
    commonName: 'certification.theremote.io',
  });

  await client.finalizeOrder(order, csr);
  const cert = await client.getCertificate(order);


  /* Done */
  db.ssl = {
    key: key.toString(),
    cert: cert.toString(),
    expire: new Date().getTime() + (30 * 24 * 60 * 60 * 1000),
  };
  save();
}

function onRequest(req, res) {
  const url = req.url.split('?').pop();
  const params = url.split('&')
    .reduce( (acc, i) => {
        const [key, val] = i.split('=');
        acc[key] = val;
        return acc;
      },
      {});

  if(restrictedNames.indexOf(params.name) !== -1) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('name not available');
    return;
  }
  // check if params are valid and client is trying to validated domain
  if(params.name && params.password && params.name.match(/^[a-z]+$/)) {
    if( db[params.name] && !passwordHash.verify(params.password, db[params.name]))
    {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('err');
      return;
    }
    db[params.name] = passwordHash.generate(params.password );
    createRecord(params.name, params.ip, params.token);
    save();
  }else if (params.name) { // client is just checking for name availability
    if(db[params.name]) {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('name not available');
      return;
    }
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('ok');
}

async function startServer() {
  await setupCerts();
  const server = https.createServer(db.ssl, onRequest);
  server.on('clientError', (err, socket) => {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });
  server.listen(8335);
}

startServer();

