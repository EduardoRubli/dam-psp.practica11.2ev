package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Estructura para cada registro de host.
type registroHost struct {
	IP        string   `json:"ip"`
	Equipo  string   `json:"equipo"`
	Sistema        string   `json:"sistema"`
	Puertos     []string `json:"puertos"`
	FirstSeen string   `json:"firstSeen"`
	LastSeen  string   `json:"lastSeen"`
	Estado    string   `json:"status"`
}

var archivoLog = "NmapLog.json"

// Carga el log existente o devuelve un slice vacío.
func cargarLog() ([]registroHost, error) {
	var hosts []registroHost
	if _, err := os.Stat(archivoLog); err == nil {
		data, err := ioutil.ReadFile(archivoLog)
		if err != nil {
			return hosts, err
		}
		err = json.Unmarshal(data, &hosts)
		if err != nil {
			return hosts, err
		}
	}
	return hosts, nil
}

// Guarda el slice de host en el archivo JSON.
func guardarLog(hosts []registroHost) error {
	data, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(archivoLog, data, 0644)
}

// Ejecuta el comando Nmap y devuelve la salida en texto.
func escanearRed() (string, error) {
	// Comando: "sudo nmap -O -p 22,80,443 192.168.1.0/24".
	cmd := exec.Command("sudo", "nmap", "-O", "-p", "22,80,443", "192.168.1.0/24")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// Filtra la salida de Nmap y extrae información de cada host.
func filtrarSalida(output string) map[string]registroHost {
	hostsFound := make(map[string]registroHost)
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Capturamos línea de IP con Regex.
	re := regexp.MustCompile(`Nmap scan report for (.+?)(?: \(([\d\.]+)\))?$`)
	// Regex para detectar línea "OS details".
	reOS := regexp.MustCompile(`OS details: (.+)`)
	// Regex para detectar puertos abiertos.
	rePort := regexp.MustCompile(`^(\d+)/tcp\s+open`)

	currentHost := ""
	for scanner.Scan() {
		line := scanner.Text()
		// Detecta la línea que indica el inicio de la información de un host
		if strings.HasPrefix(line, "Nmap scan report for") {
			match := re.FindStringSubmatch(line)
			if len(match) > 0 {
				var equipo, ip string
				if match[2] != "" {
					// Formato: equipo (IP)
					equipo = strings.TrimSpace(match[1])
					ip = strings.TrimSpace(match[2])
				} else {
					// Formato: solo IP o equipo sin paréntesis
					ip = strings.TrimSpace(match[1])
					equipo = ip
				}
				currentHost = ip
				hostsFound[ip] = registroHost{
					IP:        ip,
					Equipo:  equipo,
					Sistema:        "",
					Puertos:     []string{},
					FirstSeen: time.Now().Format(time.RFC3339),
					LastSeen:  time.Now().Format(time.RFC3339),
					Estado:    "conectado",
				}
			}
		} else if strings.Contains(line, "Sistema details:") {
			if currentHost != "" {
				match := reOS.FindStringSubmatch(line)
				if len(match) > 0 {
					entry := hostsFound[currentHost]
					entry.Sistema = strings.TrimSpace(match[1])
					hostsFound[currentHost] = entry
				}
			}
		} else if rePort.MatchString(line) {
			if currentHost != "" {
				match := rePort.FindStringSubmatch(line)
				if len(match) > 0 {
					entry := hostsFound[currentHost]
					entry.Puertos = append(entry.Puertos, match[1])
					hostsFound[currentHost] = entry
				}
			}
		}
	}
	return hostsFound
}

// Busca en el log una entrada con estado "conectado" para una IP.
// Devuelve el índice de la entrada o -1 si no se encuentra.
func buscaHostConectado(logEntries []registroHost, ip string) int {
	for i, entry := range logEntries {
		if entry.IP == ip && entry.Estado == "conectado" {
			return i
		}
	}
	return -1
}

// Verifica si la IP del host está en el escaneo actual.
func existeHost(scanned map[string]registroHost, ip string) bool {
	_, found := scanned[ip]
	return found
}

func main() {
	// Cargamos log existente o creamos uno nuevo.
	logEntries, err := cargarLog()
	if err != nil {
		log.Fatalf("Error al cargar el log: %v", err)
	}

	// Ejecutamos escaneos de Nmap cada minuto.
	for {
		fmt.Println("Ejecutando Nmap...")
		output, err := escanearRed()
		if err != nil {
			log.Printf("Error ejecutando Nmap: %v", err)
		} else {
			fmt.Println("Procesando salida de Nmap...")
			scannedHosts := filtrarSalida(output)
			now := time.Now().Format(time.RFC3339)

			// Para cada host detectado en el escaneo:
			for ip, scannedEntry := range scannedHosts {
				idx := buscaHostConectado(logEntries, ip)
				if idx >= 0 {
					// Host conectado, actualizamos lastSeen.
					logEntries[idx].LastSeen = now
				} else {
					// El host no tiene registro conectado, se crea uno nuevo.
					fmt.Printf("Nuevo host detectado: %s\n", ip)
					logEntries = append(logEntries, scannedEntry)
				}
			}

			// Para cada entrada del log marcada como "conectado",
			// se actualizará a "desconectado" si no se encuentra.
			for i, entry := range logEntries {
				if entry.Estado == "conectado" && !existeHost(scannedHosts, entry.IP) {
					logEntries[i].LastSeen = now
					logEntries[i].Estado = "desconectado"
					fmt.Printf("Host %s desconectado en %s\n", entry.IP, now)
				}
			}

			// Guardamos el log actualizado.
			err = guardarLog(logEntries)
			if err != nil {
				log.Printf("Error guardando el log: %v", err)
			}
		}

		// Espera de 1 minuto entre escaneos.
		time.Sleep(1 * time.Minute)
	}
}
