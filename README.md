# Little Printer Content Source
This project stands up a web interface and set of services to make Little Printers more fun. 
## Planned Features
### Source content
- [ ] Weather
- [ ] Quotes
- [ ] Jokes
- [ ] Top Headlines
- [ ] Reddit Frontpage
- [ ] Cat Facts
- [ ] Simple text messages
- [ ] Pretty text messages
- [ ] Drawing messages
- [ ] Image messages
- [ ] QR code text and links
- [ ] Message scheduling
- [x] User accounts

## How to build / run
To build static/style.css, run:
```sh
npx tailwindcss build -i .\src\input.css -o .\static\style.css
```
include the `-w` flag to run tailwindcss in watch mode.

To run the application, we use flask:
```sh
python ./app.py
```
If you want to run it in development mode (recommended during development, of course!), run this first (via powershell)
```powershell
$env:FLASK_ENV = "development"
```