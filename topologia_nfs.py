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

    # Mapeia /lib/modules do host para permitir o funcionamento do nfs-kernel-server
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

    info("*** Configurando Alice e iniciando servicos NFS\n")
    alice.cmd("echo '10.200.0.1 alice' >> /etc/hosts")
    alice.cmd("service rpcbind start")
    alice.cmd("service nfs-kernel-server start")
    alice.cmd("services.sh &")

    info("*** Executando CLI\n")
    CLI(net)

    info("*** Encerrando laboratorio\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topology()
