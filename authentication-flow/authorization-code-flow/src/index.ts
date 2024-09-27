import express from 'express'

const app = express()

app.get('/login', (req, res) => {
  const loginParams = new URLSearchParams({
    client_id: 'fullcycle_client',
    redirect_uri: 'http://localhost:3000/callback',
    response_type: 'code',
    scope: 'openid'
  })
  const url = `http://localhost:8080/realms/fullcycle_realm/protocol/openid-connect/auth?${loginParams.toString()}`
  res.redirect(url)
})

app.get('/callback', async (req, res) => {
  console.log(req.query)
  const { code } = req.query

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

  res.json(result)
})

app.listen(3000, () => console.log('Litenning on port 3000'))