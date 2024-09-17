import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'login.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_database/firebase_database.dart';
import 'package:http/http.dart' as http;

final DBref = FirebaseDatabase.instance.reference();

class HomePage extends StatefulWidget {
  @override
  _HomePageState createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  int led = 0;
  bool isLoading = false;
  int miraiValue = 0;
  bool isLedOn = false;

  @override
  void initState() {
    super.initState();
    isLoading = true;
    getLed();
    listenMirai(context);
  }

  Future<void> getLed() async {
    await DBref.child('LED').once().then((DatabaseEvent event) {
      DataSnapshot snapshot = event.snapshot;
      dynamic value = snapshot.value;

      if (value != null) {
        setState(() {
          led = value as int;
        });
      } else {
        print('Invalid value received: $value');
      }
    });
    setState(() {
      isLoading = false;
    });
  }

  void buttonPressed() {
    int newLedState = isLedOn ? 0 : 1; // Toggle the LED state
    DatabaseReference ledRef = DBref.child('LED');

    ledRef.set(newLedState).then((_) {
      // If setting the LED state in the database is successful, update local state
      setState(() {
        isLedOn = !isLedOn; // Toggle the local state variable
      });
    }).catchError((error) {
      // If there's an error, print the error message
      print('Error updating LED state: $error');
    });
  }


  void listenMirai(BuildContext context) {
    DatabaseReference Mirai = FirebaseDatabase.instance.ref().child("Mirai");
    DatabaseReference Buz = FirebaseDatabase.instance.ref().child("BUZ");

    Mirai.onValue.listen((DatabaseEvent event) {
      setState(() {
        miraiValue = event.snapshot.value as int;
        if (miraiValue == 1) {
          showDialog(
            context: context,
            builder: (BuildContext context) {
              return AlertDialog(
                title: Text('Mirai Detected'),
                content: Text('Mirai has been detected!'),
                actions: [
                  TextButton(
                    onPressed: () {
                      Navigator.of(context).pop();
                    },
                    child: Text('OK'),
                  ),
                ],
              );
            },
          );

          Buz.set(1);
        } else {
          Buz.set(0);
        }
      });
    });
  }


  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Home Page'),
        actions: [
          PopupMenuButton<String>(
            child: Icon(Icons.more_vert, color: Colors.black),
            onSelected: (String value) async {
              switch (value) {
                case 'logout':
                  {
                    SharedPreferences prefs =
                    await SharedPreferences.getInstance();
                    prefs.setBool('isLoggedIn', false);
                    FirebaseAuth.instance.signOut().then((value) {
                      Navigator.of(context).push(MaterialPageRoute(
                          builder: ((ctx) {
                            return LoginPage();
                          })));
                    });
                  }
                  break;
                default:
              }
            },
            itemBuilder: (BuildContext context) =>
            <PopupMenuEntry<String>>[
              PopupMenuItem<String>(
                value: 'logout',
                child: Text('Logout'),
              ),
            ],
          ),
          SizedBox(width: 10),
        ],
      ),
      body: Stack(
        children: [
          Container(
            decoration: BoxDecoration(
              image: DecorationImage(
                image: AssetImage('assets/images/download.jpg'),
                fit: BoxFit.cover,
              ),
            ),
          ),
          Center(
            child: miraiValue == 1
                ? Container(
              color: Colors.black.withOpacity(0.7),
              // Black background with opacity
              padding: EdgeInsets.all(20),
              // Add padding for better visibility
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: <Widget>[
                  Text(
                    'Warning: Mirai botnet detected in network \n Actions taken: Bulb set to off\nPlease do switch off the power system',
                    style: TextStyle(
                      color: Colors.red,
                      // Text color set to white for contrast
                      fontSize: 20,
                    ),
                    textAlign: TextAlign.center, // Center align the text
                  ),
                ],
              ),
            )
                : InkWell(
              onTap: buttonPressed,
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Image.asset(
                    isLedOn
                        ? "assets/images/bulbon.png"
                        : "assets/images/bulboff.png",
                    width: 250,
                    height: 350,
                  ),
                  SizedBox(height: 10),
                  Text(
                    isLedOn ? "Turn Bulb Off" : "Turn Bulb On",
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}