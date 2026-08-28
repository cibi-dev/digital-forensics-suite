-- Forensic Database Seed Data
-- 6 Realistic crime incidents with associated suspects, evidences, and victims.

PRAGMA foreign_keys = ON;

-- ============================================================================
-- Incident 1: Robo con intimidación
-- ============================================================================
INSERT INTO incidents (id, incident_type, date_approx, location, risk_level, summary) VALUES (
    1,
    'Robo con intimidación',
    '2026-03-12 21:30',
    'Av. Providencia 1420, Providencia, Santiago',
    'Alto',
    'Asalto a mano armada en farmacia de turno. Dos sujetos ingresaron amenazando con armas de fuego al personal y sustrajeron recaudación en efectivo y medicamentos psicotrópicos sujetos a control legal.'
);

INSERT INTO suspects (incident_id, alias_or_name, physical_description, status) VALUES
(1, 'El Chino', 'Masculino, ~28 años, 1.75m, contextura delgada, tatuaje de dragón en antebrazo derecho', 'Detenido'),
(1, 'El Flaco', 'Masculino, ~25 años, 1.80m, tez morena, vestía polerón negro con capucha y jeans oscuros', 'En fuga');

INSERT INTO evidences (incident_id, item, location_found) VALUES
(1, 'Vaina servida calibre 9mm marca Luger', 'Piso frente al mostrador de caja principal'),
(1, 'Grabación DVR de cámara de seguridad domo HD', 'Rack de servidores en trastienda de farmacia'),
(1, 'Pasamontañas de lana negro con restos biológicos para ADN', 'Vereda exterior a 15 metros del acceso principal');

INSERT INTO victims (incident_id, name_or_identity, injury_status, statement_summary) VALUES
(1, 'Camila Valenzuela', 'Crisis de pánico severa y contusión leve en muñeca izquierda', 'Cajera de turno declara que fue encañonada directamente y obligada a abrir la caja registradora y el depósito de fármacos controlados.');

-- ============================================================================
-- Incident 2: Homicidio frustrado
-- ============================================================================
INSERT INTO incidents (id, incident_type, date_approx, location, risk_level, summary) VALUES (
    2,
    'Homicidio frustrado',
    '2026-04-05 02:15',
    'Calle San Diego 890, Santiago Centro',
    'Crítico',
    'Disparos reiterados en vía pública tras discusión entre individuos en las afueras de local nocturno. La víctima recibió tres impactos balísticos en tórax y abdomen a corta distancia.'
);

INSERT INTO suspects (incident_id, alias_or_name, physical_description, status) VALUES
(2, 'Mateo Morales alias El Pela', 'Masculino, 34 años, 1.70m, calvo, cicatriz lineal visible en mejilla izquierda', 'En fuga'),
(2, 'Conductor no identificado', 'Masculino, contextura gruesa, conducía sedán gris oscuro polarizado sin placa patente delantera', 'Desconocido');

INSERT INTO evidences (incident_id, item, location_found) VALUES
(2, 'Pistola Glock 17 calibre 9mm con número de serie borrado químicamente', 'Bajo contenedor de basura a 50 metros del sitio del suceso'),
(2, 'Cargador extendido con 12 cartuchos 9mm sin percutar', 'Canaleta de desagüe pluvial en calle San Diego'),
(2, 'Hisopado de muestra hematológica pardo rojiza (sangre)', 'Calzada frente a acceso principal de discoteca');

INSERT INTO victims (incident_id, name_or_identity, injury_status, statement_summary) VALUES
(2, 'Ignacio Riquelme', 'Heridas penetrantes por proyectil balístico con compromiso visceral en hemitórax derecho y abdomen', 'Víctima hospitalizada con riesgo vital; acompañante declara emboscada directa tras disputa verbal previa al interior del recinto.');

-- ============================================================================
-- Incident 3: Fraude informático
-- ============================================================================
INSERT INTO incidents (id, incident_type, date_approx, location, risk_level, summary) VALUES (
    3,
    'Fraude informático',
    '2026-05-18 10:00',
    'Plataforma Digital Bancaria / IP remota en Las Condes, Santiago',
    'Medio',
    'Ataque tipo Man-in-the-Middle y suplantación de identidad en portal corporativo bancario mediante phishing avanzado, resultando en desvío no autorizado de fondos empresariales por $45.000.000 CLP.'
);

INSERT INTO suspects (incident_id, alias_or_name, physical_description, status) VALUES
(3, 'Rodrigo Silva alias Vector Krypton', 'Masculino, 31 años, 1.78m, contextura media, especialista en infraestructura de redes y seguridad informática', 'Identificado');

INSERT INTO evidences (incident_id, item, location_found) VALUES
(3, 'Notebook Lenovo Legion con entorno Kali Linux y scripts de redirección DNS automatizados', 'Habitación 402, Calle El Golf 230, Las Condes'),
(3, 'Pendrive SanDisk Extreme 64GB con base de datos de credenciales bancarias interceptadas', 'Mochila incautada durante allanamiento judicial'),
(3, 'Dump de tráfico de red en formato PCAP con trazas de túneles VPN y proxies cifrados', 'Servidor VPS interceptado judicialmente en centro de datos');

INSERT INTO victims (incident_id, name_or_identity, injury_status, statement_summary) VALUES
(3, 'Inversiones y Asesorías Los Andes SpA (Rep: Mario Gómez)', 'Sin daños corporales (Perjuicio económico directo de $45.000.000 CLP)', 'Tesorero señala que ingresó a enlace aparentemente fidedigno para pago de nómina y los montos fueron redirigidos a cuentas receptoras intermedias.');

-- ============================================================================
-- Incident 4: Tráfico de estupefacientes
-- ============================================================================
INSERT INTO incidents (id, incident_type, date_approx, location, risk_level, summary) VALUES (
    4,
    'Tráfico de estupefacientes',
    '2026-06-22 18:45',
    'Pasaje Los Aromos 554, La Pintana, Santiago',
    'Crítico',
    'Operativo policial antidrogas con entrada y registro en centro de acopio, dosificación y distribución barrial de sustancias ilícitas fuertemente fortificado con rejas perimetrales.'
);

INSERT INTO suspects (incident_id, alias_or_name, physical_description, status) VALUES
(4, 'Carlos Bustamante alias El Patrón Chico', 'Masculino, 42 años, 1.68m, robusto, barba candado, líder operativo de la red de microtráfico', 'Detenido'),
(4, 'Jessica Parra alias La Rubia', 'Femenino, 38 años, 1.60m, cabello rubio teñido, encargada de pesaje y empaque de papelinas', 'Detenido'),
(4, 'Soldado centinela no identificado', 'Masculino joven, contextura delgada, vestimenta deportiva negra, huyó por tejados colindantes', 'Desconocido');

INSERT INTO evidences (incident_id, item, location_found) VALUES
(4, '4.2 kg de Clorhidrato de Cocaína distribuidos en 4 ladrillos prensados y envoltorios dosificados', 'Falso fondo de ropero empotrado en dormitorio principal'),
(4, 'Balanza digital de precisión y 500 bolsas de polietileno con sellado hermético', 'Mesa central de cocina del inmueble'),
(4, '$3.850.000 en billetes de diversa denominación en moneda nacional producto de ventas ilícitas', 'Caja de caudales metálica oculta bajo tarima de piso de madera');

INSERT INTO victims (incident_id, name_or_identity, injury_status, statement_summary) VALUES
(4, 'Comunidad Vecinal Pasaje Los Aromos', 'Vulneración de la seguridad comunitaria y convivencia pacífica', 'Vecinos mediante denuncia reservada reportan constante presencia de sujetos armados, disputas territoriales y transacciones de estupefacientes 24/7.');

-- ============================================================================
-- Incident 5: Hurto agravado
-- ============================================================================
INSERT INTO incidents (id, incident_type, date_approx, location, risk_level, summary) VALUES (
    5,
    'Hurto agravado',
    '2026-07-09 14:10',
    'Tienda por departamento Falabella, Mall Plaza Vespucio, La Florida',
    'Bajo',
    'Sustracción de dispositivos electrónicos de alta gama utilizando bolsas con blindaje artesanal de aluminio ("bolsas biónicas") para neutralizar las antenas de radiofrecuencia de los sensores de salida.'
);

INSERT INTO suspects (incident_id, alias_or_name, physical_description, status) VALUES
(5, 'Marcela Toledo', 'Femenino, 26 años, 1.63m, contextura delgada, cabello castaño recogido, vestimenta formal', 'Detenido'),
(5, 'Cristóbal Vega alias El Ganso', 'Masculino, 29 años, 1.72m, contextura media, captado en circuito cerrado como vigilante exterior', 'Identificado');

INSERT INTO evidences (incident_id, item, location_found) VALUES
(5, '2 Bolsas de compras forradas internamente con 6 capas de papel aluminio y cinta de embalaje', 'En posesión directa de la imputada al momento de la interceptación'),
(5, '5 Smartphones iPhone 15 Pro Max de 256GB nuevos y sellados en sus cajas', 'Al interior de las bolsas blindadas incautadas'),
(5, 'Desacoplador magnético universal de sensores rígidos de seguridad', 'Bolsillo secreto en cartera de mano de la imputada');

INSERT INTO victims (incident_id, name_or_identity, injury_status, statement_summary) VALUES
(5, 'Falabella Retail S.A. (Rep: Guardia Juan Pérez)', 'Sin lesiones físicas', 'Jefe de seguridad privada relata que detectó por monitores la manipulación sospechosa en vitrinas y procedió a retener a la imputada antes de abordar vehículo de escape.');

-- ============================================================================
-- Incident 6: Extorsión
-- ============================================================================
INSERT INTO incidents (id, incident_type, date_approx, location, risk_level, summary) VALUES (
    6,
    'Extorsión',
    '2026-08-01 11:30',
    'Restaurante Sabor Criollo, Barrio Franklin, Santiago',
    'Alto',
    'Exigencia extorsiva continua ("cobro de vacuna") a comerciante gastronómico bajo amenazas explícitas de atentado incendiario contra el establecimiento comercial y daños físicos a su grupo familiar directo.'
);

INSERT INTO suspects (incident_id, alias_or_name, physical_description, status) VALUES
(6, 'Yeico alias Cabecilla de Célula Extorsiva', 'Masculino, ~30 años, contextura atlética, 1.82m, acento caribeño, vestimenta deportiva oscura', 'En fuga'),
(6, 'Motorista repartidor de encomiendas extorsivas', 'Masculino joven, casco integral negro con calcomanía de calavera, motocicleta Yamaha FZ roja', 'Identificado');

INSERT INTO evidences (incident_id, item, location_found) VALUES
(6, 'Panfleto manuscrito con amenazas de muerte, exigencia de $500.000 CLP semanales y número WhatsApp', 'Bajo la cortina metálica del restaurante'),
(6, 'Registro de mensajes de texto y audios de voz amenazantes en mensajería instantánea', 'Teléfono móvil inteligente personal de la víctima'),
(6, 'Sobre manila cerrado con fotografías de seguimiento tomadas al frontis del colegio de los hijos de la víctima', 'Buzón de correspondencia exterior del local');

INSERT INTO victims (incident_id, name_or_identity, injury_status, statement_summary) VALUES
(6, 'Manuel Carrasco', 'Cuadro de estrés agudo severo y crisis de ansiedad', 'Propietario gastronómico declara que desconocidos dejaron panfleto exigiendo pago de cuota semanal de seguridad o quemarían el local con clientes adentro.');
