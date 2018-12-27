<?php
/*
 * Clase que contiene funcionalidades utles para la comunicacion
 * con el servicio de descarga masiva del SAT
 *
 * @Autor Mexagon.net / Carlos Reyes
 * @Fecha Diciembre 2018
 */

 class Utils{
    /*********************************
     *      METODOS PUBLICOS
     *********************************/
    public $password = "";
    public $archivoCer = "";
    public $archivoKey = "";
    public $certificadoB64 = "";
    public $diffMinServSat = 360;
    public $temps = array();
    public $response = "";
    public $error = "";
    public $codigo = "";

    /*********************************
     *      METODOS PRIVADOS
     *********************************/
    private $curl = null;

    /*********************************
     *      METODOS PUBLICOS
     *********************************/
    /*
     * Constructor de la clase
     */
    public function __construct() {
    }

    /*
     * Metodo que realiza la comunicacion con CURl
     */
     public function transmisionCURl( $url , $msj , $headers , $operacion ) {
        $this->curl = curl_init();
        curl_setopt_array( $this->curl , array (
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST  => 'POST',
            CURLOPT_POSTFIELDS     => $msj,
            CURLOPT_HTTPHEADER     => $headers
        ));

        $this->response = curl_exec( $this->curl );
        $this->error    = curl_error( $this->curl );
        $this->codigo   = curl_getinfo( $this->curl , CURLINFO_HTTP_CODE );

        if ( $this->error ) {
            throw new Exception( "[".$operacion."] Error en la comunicacion CURL " . $this->error . '/' . $this->codigo );
        } else {
            if( $this->codigo != 200 ) {
                    throw new Exception( "[".$operacion."] Error codigo: " . $this->codigo . " Con el mensaje: " . $this->response );
                } else {
                    // Comunicacion exitosa
            }
        }
     }

    /*
     * Metodo que obtiene los elementos de la fiel
     */
    public function getFiel() {
        $this->password    = "2912lojo";
        $this->archivoCer  = "resc840317j72.cer";
        $this->archivoKey  = "resc840317j72.key";
        $this->certificadoB64 = $this->obtieneCertificado();
    }

    /* Obtencion del certificado e.firma en base 64 */
    public function obtieneCertificado() {
        $certificado = base64_encode( file_get_contents( $this->archivoCer ) );
        return $certificado;
    }

    /*
     * Metodo que regresa el digest value del mensaje
     */
    public function digestValue( $xml ) {
        $digestValue  = sha1( $xml , true );
        return base64_encode( $digestValue );
    }

    /*
     * Metodo que obtiene el sello a envar en el mensaje
     */
    public function sello( $xml ) {
        $x = new DOMDocument( "1.0", "ISO-8859-15" );
        $x->loadXML( $xml );
        return $this->llavePrivada( $x->C14N() );
    }

    /* Creacion de identificadores */
    public function idty() {
        return array( rand( 11111 , 99999 ) , rand( 11111 , 99999 ) );
    }

    /* Depuracion de archivos */
    public function gc() {
        foreach( $this->temps AS $temp ) {
            unlink( $temp );
        }
    }

    /*********************************
     *      METODOS PRIVADOS
     *********************************/

    /* Firmado y creacion de sello digital */
    private function llavePrivada( $nodo ) {
        $crypttext     = '';
        exec( '/usr/bin/openssl pkcs8 -inform DER -in ' . $this->archivoKey . ' -out ' . $this->archivoKey . '.pem -passin pass:' . $this->password );
        $this->temps[] = $this->archivoKey . '.pem';
        $pkeyid        = openssl_get_privatekey( file_get_contents( $this->archivoKey . '.pem' ) );
        openssl_sign( $nodo , $crypttext , $pkeyid , OPENSSL_ALGO_SHA1 );
        openssl_free_key( $pkeyid );
        return base64_encode( $crypttext );
    }

 }
