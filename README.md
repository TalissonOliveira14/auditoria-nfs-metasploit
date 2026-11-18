# Análise e Auditoria de Vulnerabilidade — NFS (Network File System)

* **Disciplina:** Segurança da Informação (UFRN / IMD)
* **Professor:** Ramon Fontes
* **Aluno:** Talisson Pereira de Oliveira e Thiago Patricio da Silva
* **Data de Entrega:** 18/11/2026

---

## 1. Vulnerabilidade Escolhida e Justificativa

* **Serviço / Protocolo:** NFS (Network File System) e RPCBind / Portmapper (Portas `111/tcp` e `2049/tcp`).
* **Classificação:** CWE-284 (*Improper Access Control* — Controle de Acesso Inadequado / Exposição Indevida de Compartilhamentos).
* **Justificativa da Escolha:** Esta vulnerabilidade não foi abordada nos exemplos do Capítulo 6 (que cobriram *vsFTPd*, *UnrealIRCd*, *PostgreSQL*, *SSH* e *DVWA*) e não foi selecionada por outras equipes na planilha oficial da turma. O vetor permite demonstrar o ciclo completo de reconhecimento de serviços RPC, verificação de configuração via Metasploit Framework (`auxiliary/scanner/nfs/nfsmount`) e auditoria de exposição de diretórios compartilhados sem controle de acesso.

---

## 2. Preparação do Ambiente e Instruções de Reprodução

Para reproduzir este laboratório em um ambiente Linux (testado no Linux Mint com Kernel `7.0.0-28-generic`), são necessários os seguintes passos de preparação:

### 2.1. Atualização das Imagens Docker
Garante-se que a imagem do nó de análise (`chuck`) contém a versão mais recente do Metasploit Framework:

```bash
docker pull ramonfontes/seguranca
docker pull ramonfontes/vulnerable
```

### 2.2. Carregamento do Módulo NFS no Kernel do Host
Como o servidor NFS dentro do contêiner `alice` depende do módulo `nfsd` do kernel do sistema hospedeiro, carrega-se o módulo no host antes de iniciar a simulação:

```bash
sudo modprobe nfsd
```

---

## 3. Topologia de Rede (Containernet)

A topologia segue o padrão de rede isolada (`10.200.0.0/24`) conectando o alvo **Alice** (`10.200.0.1`) e a estação de análise **Chuck** (`10.200.0.2`) através de um switch virtual (`s1`).

### Código-Fonte (`topologia_nfs.py`)

```python
#!/usr/bin/python
	'''@author: Talisson Pereira de Oliveira
   Disciplina: Segurança da Informação - UFRN/IMD'''

import os
from containernet.net import Containernet
from containernet.cli import CLI
from mininet.log import info, setLogLevel

def topology():
    "Create a network."
    net = Containernet(ipBase='10.200.0.0/24')

    info("*** Criando nos\n")
    s1 = net.addSwitch('s1', failMode="standalone")

    alice = net.addDocker(
        'alice',
        dimage="ramonfontes/vulnerable",
        cpu_shares=20,
        volumes=['/lib/modules:/lib/modules:ro'],
        privileged=True,
        mac='00:00:00:00:00:01'
    )

    chuck = net.addDocker(
        'chuck',
        dimage="ramonfontes/seguranca",
        cpu_shares=20,
        mac='00:00:00:00:00:02'
    )

    info("*** Conectando os nos\n")
    net.addLink(s1, alice)
    net.addLink(s1, chuck)

    info("*** Inicializando rede\n")
    net.build()
    s1.start([])

    info("*** Configurando Alice\n")
    alice.cmd("echo '10.200.0.1 alice' >> /etc/hosts")
    alice.cmd("services.sh &")

    info("*** Executando CLI\n")
    CLI(net)

    info("*** Encerrando laboratorio\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topology()
```

### Adaptações no Ambiente de Contêineres
Como o sistema de arquivos padrão de contêineres Docker (`overlay2`) não suporta exportação NFS nativa sem `fsid` e os módulos do host utilizam compressão `.zst`, ativou-se o compartilhamento de auditoria em `tmpfs` no nó `alice` e iniciaram-se os daemons RPC/NFS diretamente:

```bash
# No host (preparando o compartilhamento de laboratório em Alice):
sudo docker exec -it mn.alice bash -c "mount -t tmpfs tmpfs /srv/nfs_publico && echo 'Arquivo de auditoria do laboratorio' > /srv/nfs_publico/info.txt && echo '/srv/nfs_publico *(ro,sync,no_subtree_check,fsid=0)' > /etc/exports && /etc/init.d/portmap restart && mount -t nfsd nfsd /proc/fs/nfsd 2>/dev/null; exportfs -ra && rpc.nfsd 8 && rpc.mountd"
```

---

## 4. Reconhecimento de Serviços (Nmap)

A partir do terminal de análise (`chuck`), realizou-se a varredura de portas e detecção de versões (`-sV`) direcionada ao alvo `10.200.0.1`:

```bash
root@chuck:/# nmap -sV -p 111,2049 10.200.0.1
```

### Saída Obtida:
```text
Starting Nmap 7.80 ( https://nmap.org ) at 2026-11-18 13:58 GMT
Nmap scan report for 10.200.0.1
Host is up (0.00057s latency).

PORT     STATE SERVICE VERSION
111/tcp  open  rpcbind 2 (RPC #100000)
2049/tcp open  nfs     3-4 (RPC #100003)
MAC Address: 00:00:00:00:00:01 (Xerox)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.64 seconds
```

**Análise:** O Nmap confirmou que os serviços `rpcbind` (porta `111/tcp`, RPC `#100000`) e `nfs` (porta `2049/tcp`, versões `3-4`, RPC `#100003`) estão ativos e aceitando conexões remotas na máquina alvo.

---

## 5. Uso do Metasploit Framework (`msfconsole`)

Com os serviços identificados, iniciou-se o console do Metasploit (`v6.5.11-dev`) no nó `chuck` para carregar e executar o módulo auxiliar de auditoria de compartilhamentos NFS (`auxiliary/scanner/nfs/nfsmount`):

```bash
msf > use auxiliary/scanner/nfs/nfsmount
msf auxiliary(scanner/nfs/nfsmount) > set RHOSTS 10.200.0.1
RHOSTS => 10.200.0.1
msf auxiliary(scanner/nfs/nfsmount) > run
```

### Saída Obtida no `msfconsole`:
```text
[*] 10.200.0.1:111        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

---

## 6. Evidência do Resultado Obtido

Complementando a verificação do portmapper, consultou-se a tabela de exportação RPC do servidor alvo utilizando o utilitário cliente NFS (`showmount -e`), confirmando que o diretório `/srv/nfs_publico` está exportado com a política curinga (`*`):

```bash
root@chuck:/# showmount -e 10.200.0.1
```

### Saída Obtida:
```text
Export list for 10.200.0.1:
/srv/nfs_publico *
```

**Impacto:** O símbolo `*` indica que qualquer endereço IP da rede pode consultar e montar o diretório remoto sem necessidade de autenticação prévia, caracterizando exposição indevida de dados e falha de controle de acesso (CWE-284).

---

## 7. Causa Raiz e Medidas de Mitigação

### 7.1. Causa Raiz da Vulnerabilidade
A vulnerabilidade decorre de uma configuração permissiva no arquivo `/etc/exports` do servidor NFS da máquina alvo, que define o compartilhamento utilizando o curinga `*` (acesso irrestrito a qualquer cliente de rede) sem mecanismos fortes de autenticação. Nas implementações tradicionais do protocolo NFS (NFSv2/NFSv3), o controle de acesso baseia-se exclusivamente na confiança do endereço IP de origem e nos identificadores locais de usuário (`UID`/`GID`), permitindo que qualquer estação na mesma sub-rede acesse os recursos exportados.

### 7.2. Medidas de Mitigação Propostas
1. **Restrição de Endereços IP no `/etc/exports`:** Substituir o curinga `*` por endereços IP ou sub-redes estritamente autorizadas (ex: `/srv/nfs_publico 10.200.0.50(ro,sync,root_squash,no_subtree_check)`), aplicando o princípio do menor privilégio.
2. **Ativação do `root_squash`:** Garantir que a diretiva `root_squash` esteja sempre habilitada (padrão seguro) para mapear requisições do usuário `root` remoto para o usuário sem privilégios `nobody`, evitando escalonamento de privilégios via sistema de arquivos.
3. **Migração para NFSv4 com Autenticação Criptográfica (Kerberos):** Atualizar a configuração para utilizar exclusivamente **NFSv4** aliado ao **RPCSEC_GSS / Kerberos (`sec=krb5p`)**, exigindo autenticação mútua e criptografia em trânsito em vez de confiar apenas no endereço IP.
4. **Segmentação de Rede e Firewall:** Filtrar as portas `111` (RPCBind) e `2049` (NFS) via regras de firewall (`iptables`/`nftables`), bloqueando o tráfego vindo de redes externas ou não confiáveis.
