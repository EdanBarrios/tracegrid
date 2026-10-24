import 'package:cloud_firestore/cloud_firestore.dart';

/// Collection references in one place.
extension TaskboardRefs on FirebaseFirestore {
  CollectionReference usersRef() => collection('users');
  CollectionReference teamsRef() => collection('teams');
  CollectionReference tasksRef(String teamId) => collection('teams').doc(teamId).collection('tasks');
}
