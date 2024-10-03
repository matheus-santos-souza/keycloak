import express from 'express'
import session from 'express-session';
import jwt from 'jsonwebtoken'

const app = express()
app.use(express.urlencoded({ extended: true }));

const memoryStore = new session.MemoryStore();

app.use(
  session({
    secret: "my-secret",
    resave: false,
    saveUninitialized: false,
    store: memoryStore,
    //expires
  })
);

const middlewareIsAuth = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  //@ts-expect-error - type mismatch
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
};

app.get('/login', (req, res) => {
  //@ts-expect-error - type mismatch
  if (req.session.user) {
    return res.redirect("/admin");
  }
  res.sendFile(__dirname + "/login.html");
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const response = await fetch(
    "http://host.docker.internal:8080/realms/fullcycle_realm/protocol/openid-connect/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: "fullcycle_client",
        grant_type: "password",
        username,
        password,
        scope: "openid",
      }).toString(),
    }
  );

  const result = await response.json();
  console.log(result);
  //@ts-expect-error - type mismatch
  req.session.user = result;
  req.session.save();

  res.redirect("/admin");
})

app.get('/callback', async (req, res) => {
  console.log(req.query)
  const { code, state } = req.query
  
  //@ts-expect-error - type mismatch
  if (req.session.user) {
    console.log(req.session)
    return res.redirect("/admin");
  }

  //@ts-expect-error - type mismatch
  if (state !== req.session.state) {
    return res.status(401).json({ message: "Unauthenticated" })
  }


  const bodyParams = new URLSearchParams({
    client_id: 'fullcycle_client',
    grant_type:'authorization_code',
    code: code as string,
    redirect_uri: 'http://localhost:3000/callback'
  })
  const url = `http://keycloak:8080/realms/fullcycle_realm/protocol/openid-connect/token`
  
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: bodyParams.toString()
  })

  const result = await response.json()
  console.log(result)

  const payloadAccessToken = jwt.decode(result.access_token) as any
  const payloadIdToken = jwt.decode(result.id_token) as any
  //@ts-expect-error - type mismatch
  if (payloadIdToken?.nonce !== req.session.nonce) {
    return res.status(401).json({ message: "Unauthenticated" })
  }

  console.log(payloadAccessToken);
  //@ts-expect-error - type mismatch
  req.session.user = payloadAccessToken;
  //@ts-expect-error - type mismatch
  req.session.access_token = result.access_token;
  //@ts-expect-error - type mismatch
  req.session.id_token = result.id_token;
  //@ts-expect-error - type mismatch
  req.session.refresh_token = result.refresh_token;
  req.session.save();

  console.log(req.session)
  return res.json(result)
})

app.get("/logout", async (req, res) => {
  // const logoutParams = new URLSearchParams({
  //   //client_id: "fullcycle_client",
  //   //@ts-expect-error
  //   id_token_hint: req.session.user.id_token,
  //   post_logout_redirect_uri: "http://localhost:3000/login",
  // });

  // req.session.destroy((err) => {
  //   console.error(err);
  // });

  // const url = `http://localhost:8080/realms/fullcycle_realm/protocol/openid-connect/logout?${logoutParams.toString()}`;
  await fetch(
    "http://host.docker.internal:8080/realms/fullcycle_realm/protocol/openid-connect/revoke",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: "fullcycle_client",
        //@ts-expect-error
        token: req.session.user.refresh_token,
      }).toString(),
    }
  );
  //response.ok verificar se a resposta está ok
  req.session.destroy((err) => {
    console.error(err);
  });
  res.redirect("/login");
});


app.get("/admin", middlewareIsAuth, (req, res) => {
  //@ts-expect-error - type mismatch
  res.json(req.session.user);
});

app.listen(3000, () => console.log('Litenning on port 3000'))