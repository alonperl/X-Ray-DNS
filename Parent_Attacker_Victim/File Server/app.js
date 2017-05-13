var express = require('express')
var app = express()
app.use(express.static('./../../rawdns'))
app.get('/', function (req, res) {
  res.send('rawdns file server')
})

app.listen(3000, function () {
  console.log('fileserver app for /rawdns/ listening on port 3000!')
})
