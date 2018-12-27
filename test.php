<?php
/*
 * Script que prueba las opreciones de descarga masiva
 */

 /* Autenticacion */
include_once './Auth.php';
$auth = new Auth();
$auth->obtieneToken();

echo $auth->token;

/* Solicitud 
$datos = array(
    'rfcEmisor' => 'API6609273E0', 'rfcReceptor' => 'RESC840317J72' , 'rfcSolicitante' => 'RESC840317J72', 
    'fechaInicial' => '2018-11-01 00:00:00', 'fechaFinal' => '2018-11-30 23:59:59', 'tipoSolicitud' => 'CFDI'
);
include_once './Solicitud.php';
$solicitud = new Solicitud();
$solicitud->generaPeticionDescarga( $datos );
echo $solicitud->response;*/
