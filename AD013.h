#ifndef AD013_FINGERPRINT_SENSOR_HEADER
#define AD013_FINGERPRINT_SENSOR_HEADER

// Use different max sizes if needed
#define AD013_MAX_PARAMS_SIZE     20

// Static Parameters Buffer
typedef struct params_st {
  char buff[AD013_MAX_PARAMS_SIZE];
  char devId[4];
  int size;
} AD013_Params;


/*! \brief Establishes a connection with the sensor
 * 
 * Use the params to provide the device Id (if differs
 * from the default one { 0xFF, 0xFF, 0xFF, 0xFF }.
 * 
 * Use '-1' for the serSpeed for looking for the
 * configured speed for the sensor. The default value
 * is 57600, however with SoftwareSerial the library
 * does not seem to support more than 19200 baud.
 * 
 * For HardwareSerial use, speeds have been successfully
 * tested up to 115200 baud.
 * 
 * The default for the serSpeed is -1 (scan for the correct
 * speed/baud).
 * 
 * The default for mySerial is Serial1 (if it exists) or
 * Serial (if it exists). If none exist, an error code is
 * returned.
 * 
 * This function returns '1' if the sensor has been found
 * and the password was correctly verified. The function
 * returns negative values for error conditions.
 * 
 */
int AD013_FindSensor(Stream     & mySerial,
                   int          serSpeed = -1,
                   AD013_Params * params   = NULL);


/*
 * !\brief Searches for a Match in the Fingerprint Database
 * 
 * This function searches for a match in the Fingerprint Database and
 * returned the matched template. This function returns '-1' if no
 * templates were matched.
 * 
 * The default timeout is 5000 ms.
 * 
 * The default threashold is 65.
 * 
 * The default SerialPort is (Serial1) if present, or (Serial) if present.
 * 
 * The default for SecurityOfficerOnly is (false). Use True to limit the
 * matching operations to the first twenty (0-19) Templates ID (usually
 * reserved for the Security Officer).
 * 
 */
int AD013_SearchTemplate (int      timeOut             = 5000,
                        int      threashold          = 50,
                        Stream * SerialPort          = NULL,
                        bool     SecurityOfficerOnly = false);


/* !\brief Clears one template from the fingerprint DB
 *  
 * Use this function to remove a single template. The templateNumber parameter
 * provides the number of the template to be removed (0-39).
 * 
 * The default SerialPort is (Serial1) if present, or (Serial) if present.
 * 
 * The function returns 1 in case of success and -1 if any error occurs.
 */
int AD013_ClearTemplates(Stream & SerialPort,
	                   int      startTemplateNumber =  0,
	                   int      endTemplateNumber   = 99);
                      
/* !\brief Clears all user templates from the fingerprint DB
 *  
 * Use this function to remove all the user's templates from the fingerprint DB.
 * The user's template are stored in IDs greater than 19 (i.e., 20+).
 * 
 * The default SerialPort is (Serial1) if present, or (Serial) if present.
 * 
 * The function returns 1 in case of success and -1 if any error occurs.
 */
int AD013_ClearUserTemplates(Stream & SerialPort);

/* !\brief Clears all the Security Officer (SO) templates from the fingerprint DB
 *  
 * Use this function to remove all the SO's templates from the fingerprint DB.
 * The SO's template are stored in IDs smaller than 20 (i.e., 0-19).
 * 
 * The default SerialPort is (Serial1) if present, or (Serial) if present.
 * 
 * The function returns 1 in case of success and -1 if any error occurs.
 */
int AD013_ClearSecurityOfficerTemplates(Stream & SerialPort);


/* !\brief Enrolls a new Finger in the Sensor's DB
 *  
 * Use this function to generate and store a new Template (5 different chars
 * compose a single Template; The AD-013 can store up to 40 Templates).
 * 
 * The function returns the ID of the storage buffer where the new Template
 * has successfully been saved. In case of errors, the function returns -1.
 *
 */
int AD013_Enroll(Stream & SerialPort, bool isSecurityOfficer);

#endif // AD013_FINGERPRINT_SENSOR_HEADER
