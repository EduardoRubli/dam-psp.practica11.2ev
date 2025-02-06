package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Modelo de datos a capturar.
type Registro struct {
	IpOrigen string `json:"ipOrigen"`
	Dominio  string `json:"dominio"`
	Equipo	 string `json:"equipo"` 
	Fecha    string `json:"fecha"`
	Hora     string `json:"hora"`
}

func main() {
	// Canal para enviar registros.
	regChan := make(chan Registro)
	var wg sync.WaitGroup

	// Lanzamos guardarRegistros como gorutina.
	wg.Add(1)
	go func() {
		defer wg.Done()
		guardarRegistros(regChan)
	}()

	// Lanzamos captura como gorutina.
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := captura(regChan)
		if err != nil {
			log.Printf("Error en captura: %v", err)
		}
		// Finalizada la captura cerramos el canal.
		close(regChan)
	}()

	// Espera que ambas gorutinas acaben.
	wg.Wait()
}

// Obtiene hostname a partir de ip con Nmap.
func obtenerHostname(ip string) string {
    // Importante, siempre es má seguro -R que -PR.
    cmdNmap := exec.Command("sh", "-c", "nmap -sn -R " + ip + " | awk '/report/{print $5}'")
    output, err := cmdNmap.Output()
    if err != nil {
    	log.Printf("Error ejecutando Nmap: %v", err)
    	return "desconocido"
    	
    }
    return strings.TrimSpace(string(output))
}

// Captura consultas DNS y envía los registros al canal.
func captura(regChan chan Registro) error {
	// `-i wlo1`: Especifica la interfaz de red a monitorear (wlo1).
	// `-Y "dns.flags.response == 0`: Filtra solo solicitudes DNS.
	// `!dns.qry.name.len == 0`: Evita capturas vacías sin nombres de dominio.
	// `-T fields`: Muestra la salida en formato de campos separados por tabulador.
	// `-e ip.src`: Extrae la IP del dispositivo que realiza la consulta DNS.
	// `-e dns.qry.name`: Extrae el nombre de dominio solicitado
	cmdShark := exec.Command("sudo", "tshark", "-i", "wlo1", "-Y", "dns.flags.response == 0 && !dns.qry.name.len == 0", "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name")
	stdout, err := cmdShark.StdoutPipe()
	if err != nil {
		return err
	}

	if err = cmdShark.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	// Mapa para controlar repeticiones.
	consultasVistas := make(map[string]bool)
	
	for scanner.Scan() {
		linea := scanner.Text()
		if !consultasVistas[linea] {
        		consultasVistas[linea] = true
        	// Separara la línea en campos (espacios o tabuladores).
        	campos := strings.Fields(linea)
        	
        	if len(campos) < 2 {
            	continue
        	}
		
		// Obtenemos hostname con Nmap.
		nombreEquipo := obtenerHostname(campos[0])
		
		now := time.Now()
		reg := Registro{
			IpOrigen: campos[0],
			Dominio:  campos[1],
			Equipo:	  nombreEquipo,
			Fecha:    now.Format("02-01-2006"),
			Hora:     now.Format("15:04:05"),
		}
		// Enviamos registro al canal.
		regChan <- reg
	       }
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return cmdShark.Wait()
}

// Recibe registros del canal y los guarda en un log.
func guardarRegistros(regChan chan Registro) {
	// Abre o crea el archivo de log en modo append.
	f, err := os.OpenFile("TsharkLog.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error al abrir el archivo de log: %v", err)
	}
	defer f.Close()

	for reg := range regChan {
		bytes, err := json.MarshalIndent(reg, "", "  ")
		if err != nil {
			log.Printf("Error al serializar registro: %v", err)
			continue
		}
		// Se añade un salto de línea al final de la entrada.
		if _, err = f.Write(append(bytes, '\n')); err != nil {
			log.Printf("Error al escribir en el archivo: %v", err)
		}
	}
}
