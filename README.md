# Detector de Intrusão Analítico (Python)

-- Ainda em desenvolvimento --

Desenvolvimento de uma Engine de detecção comportamental para logs de trafégo de rede (Simulação NS2/CSV).
Implementação de um algoritmo que analisa taxa de envio, tamanho do pacote e protocolo utilizado para identificar se uma atividade é suspeita.
Arquitetura de software orientada a objetos focada em alta performance, utilizando generators do Python para processamento eficiente de grandes volumes de dados.

## Lógica do Algoritmo de Detecção (Detection Engine):

O coração do sistema analisa os eventos de rede em tempo real e aplica uma pontuação de risco cumulativa baseada em três regras principais de comportamento malicioso:

### 1. Detecção por Volume com Janela de Tempo (Rate Limiting)
* **Conceito:** Picos isolados de tráfego podem ser legítimos (ex: carregamento de uma página pesada). Um ataque de negação de serviço (DoS), porém, mantém uma taxa de pacotes alta e constante.
* **Lógica Aplicada:** O motor monitora a coluna `PKT_RATE`. Se a taxa passar de 300 pacotes por segundo, o sistema calcula o intervalo de tempo (`interval`) entre o pacote atual e o anterior do mesmo IP:
  * Se o intervalo for **menor que 1 segundo**, o risco sobe rapidamente (+5 pontos), indicando um ataque ativo.
  * Taxa de 300 pacotes recebem +1 ponto, o contador pode ser zerado, mas até chegar no limite, mesmo que o intervalo seja maior que 1 segundo, o contador de risco incrementa 1 (1 < intervalo <= 300).

### 2. Assinatura de Inundação UDP/CBR (DDoS Flooding)
* **Conceito:** Ataques de negação de serviço volumétricos frequentemente inundam a rede com pacotes UDP de tamanho idêntico e taxa constante para esgotar a banda do servidor.
* **Lógica Aplicada:** Caso o protocolo seja `b'udp'` ou `b'cbr'`, o motor verifica se a taxa está acima de 300. Além disso, o sistema compara o tamanho do pacote atual com o anterior (`last_pkt_size`). Se o tamanho se repetir consistentemente, a pontuação de risco é severamente penalizada.

### 3. Pacotes ICMP Anormais (Ping of Death / Oversized Ping)
* **Conceito:** Pacotes de ping legítimos raramente passam de algumas dezenas de bytes. Pacotes ICMP artificialmente gigantes podem ser usados para travar ou sobrecarregar interfaces de rede.
* **Lógica Aplicada:** O motor isola pacotes do tipo `b'ping'`. Se o tamanho do pacote (`PKT_SIZE`) for maior ou igual a **1500 bytes** (o limite padrão de MTU da maioria das redes), o IP recebe +4 pontos de risco imediatamente.

Antes da aplicação das regras de detecção, a Engine calcula dinamicamente o intervalo de tempo entre os pacotes de cada IP. Para garantir a alta performance do sistema e evitar o vazamento de memória (*Memory Leak*) com falsos positivos de IPs que cessaram a atividade, o motor possui uma política de expiração estrita:

* **Mecanismo de Clean Up:** Se um IP suspeito passar mais de 5 minutos (300 segundos) sem registrar nenhuma atividade maliciosa, o método `delete_risk` é acionado, removendo completamente o IP do histórico de falhas. Isso garante que, caso o IP volte a se comunicar no futuro, seu ciclo de análise seja reiniciado do zero de forma justa

### Futuras Implementações

##### 1. Maior opções de visualização dos logs

A visualização padrão será o que o programa faz atualmente, porém pretendo adicionar opções para visualizar os dados brutos e maneiras de customizar o output da análise, como, por exemplo:

1. Filtrar valores únicos;
2. Filtrar por protocolos;
3. Filtrar por IPs;

##### 2. Interface

##### 3. Geração de Gráficos

Pretendo utilizar as bibliotecas pandas e matplotlib para gerar gráficos sobre os filtros que o usuário escolher.

