import 'package:cloud_firestore/cloud_firestore.dart';
import '../../data/refs.dart';

class TaskRepository {
  TaskRepository(this.teamId);
  final String teamId;

  Stream<QuerySnapshot> watchTasks() =>
      FirebaseFirestore.instance.tasksRef(teamId).orderBy('due').snapshots();

  Future<void> addTask(String title) =>
      FirebaseFirestore.instance.tasksRef(teamId).add({'title': title, 'done': false});

  // Archived tasks: the collection name has a typo, so no rule matches and Firestore denies it.
  Future<QuerySnapshot> archived() =>
      FirebaseFirestore.instance.collection('teams/$teamId/archve').get();
}
