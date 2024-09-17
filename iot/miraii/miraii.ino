#define LED_PIN 5 // GPIO 5 connected to resistor
const int BUZZZER_PIN = 15;
#include<Wire.h>

#include<ESP8266WiFi.h>

#include <Firebase_ESP_Client.h>




 //Pin number of the LED
 #define FIREBASE_AUTH  "" //Your Firebase Web API Key
 #define FIREBASE_HOST  "" //Your Firebase URL
 #define WIFI_SSID ""     //Your WIFI SSID
 #define WIFI_PASSWORD   "" //Your WIFI Password



#include "addons/TokenHelper.h"
//Provide the RTDB payload printing info and other helper functions.
#include "addons/RTDBHelper.h"

const int relayPin = 5;
FirebaseAuth auth;
FirebaseConfig config;
FirebaseData fbdo;
int count = 0;
bool signupOK = false;


unsigned long sendDataPrevMillis = 0;
void setup() {
   WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting to Wi-Fi");
  while (WiFi.status() != WL_CONNECTED){
    Serial.print(".");
    delay(300);
  }
  Serial.println();
  Serial.print("Connected with IP: ");
  Serial.println(WiFi.localIP());
  Serial.println();

config.api_key =  FIREBASE_AUTH;

  /* Assign the RTDB URL (required) */
  config.database_url = FIREBASE_HOST;
  /* Sign up */
  if (Firebase.signUp(&config, &auth, "", "")){
    Serial.println("ok");
    signupOK = true;
  }
  else{
    Serial.printf("%s\n", config.signer.signupError.message.c_str());
  }

  /* Assign the callback function for the long running token generation task */
  //see addons/TokenHelper.h
   config.token_status_callback = tokenStatusCallback;
  Firebase.begin(&config, &auth);
  Firebase.reconnectWiFi(true);
 
  pinMode(LED_PIN, OUTPUT);
  pinMode(BUZZZER_PIN, OUTPUT);
}

void loop() {
  
  if (Firebase.ready() && signupOK && (millis() - sendDataPrevMillis > 1000 || sendDataPrevMillis == 0)){
    //since we want the data to be updated every second
    sendDataPrevMillis = millis();
   
  if (Firebase.RTDB.getInt(&fbdo,"/LED")){ // Your Firebase data path
 int   LED = fbdo.intData();
    if(LED== 1){
       digitalWrite(LED_PIN,HIGH);
      Serial.println("LIGHT is ON");
    }
    else if (LED == 0){
      digitalWrite(LED_PIN, LOW);
      Serial.println("LIGHT is OFF");
    }
  }
    else{
      Serial.println(fbdo.errorReason());
    }
    delay(3000);
     
  if (Firebase.RTDB.getInt(&fbdo,"/BUZ")){ // Your Firebase data path
 int   BUZ = fbdo.intData();
    if(BUZ == 1){
      
      digitalWrite(BUZZZER_PIN, HIGH);
      Serial.println("Buzzer is ON");
    }
    else if (BUZ == 0){
      digitalWrite(BUZZZER_PIN, LOW); 
      Serial.println("Buzzer is OFF");
    }
  }
    else{
      Serial.println(fbdo.errorReason());
    }
    delay(3000);
   
}
        // turn the LED on (HIGH is the voltage level)
               // wait for a second
     // turn the LED off by making the voltage LOW
  delay(1000);// wait for a second
}
