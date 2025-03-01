    import http from 'http';
    import fs from 'fs';
    import path from 'path';
    import express from 'express';
    import { fileURLToPath } from 'url';

    const PORT = 8070;

    // Get the current directory name
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);




http.createServer((req, res) => {
  // Determine the file path based on the request URL
  let filePath = path.join(__dirname, 'views', req.url === '/' ? 'login.html' : req.url);

  // Map file extensions to content types
  const extname = path.extname(filePath);
  const contentType = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.gif': 'image/gif',
  }[extname] || 'application/octet-stream';

  // Check if the file exists
  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/html' });
        res.end('<h1>404 Not Found</h1>');
      } else {
        res.writeHead(500);
        res.end('Server Error');
      }
    } else {
      // Serve the file
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    }
  });
}).listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
