export default function handler(req, res) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end('{"status":"ok"}');
}
