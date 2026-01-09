const http = require('http');

const port = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.end('Hello from node-hello (LAB-1)\n');
});

server.listen(port, () => {
  console.log(`node-hello listening on ${port}`);
});
