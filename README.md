## Manual de Uso

### 1. Criar e ativar o ambiente virtual

```bash
# Cria o ambiente
python -m venv venv

# Ativa no Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Ativa no Windows (CMD)
venv\Scripts\activate.bat

# Ativa no Linux/macOS
source venv/bin/activate

```

### 2. Instalar dependências Python

```bash
pip install -r requirements.txt
```

### 3. Instalar ferramentas externas

#### Nikto

Debian/Ubuntu:

```bash
sudo apt install nikto
```

Windows (Chocolatey):

```bash
choco install nikto
```

#### Wappalyzer CLI

```bash
npm install -g wappalyzer
```

### Executar o ReconApp

```bash
python -m reconapp.gui
```
