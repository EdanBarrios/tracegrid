import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:cloud_functions/cloud_functions.dart';
import '../../data/refs.dart';

class TeamActions {
  final _functions = FirebaseFunctions.instance;

  Future<DocumentSnapshot> team(String id) => FirebaseFirestore.instance.teamsRef().doc(id).get();

  Future<DocumentSnapshot> invite(String code) =>
      FirebaseFirestore.instance.collection('invites').doc(code).get();

  Future<void> acceptInvite(String code) => _call('acceptInvite', {'code': code});

  Future<void> exportTeam(String teamId) => _call('exportTeamData', {'teamId': teamId});

  // Renamed on the server to sendWeeklyDigest; this call now fails.
  Future<void> sendDigest(String teamId) => _call('sendDigest', {'teamId': teamId});

  Future<Map<String, dynamic>> _call(String name, Map<String, Object?> payload) async {
    final result = await _functions.httpsCallable(name).call<Map<String, dynamic>>(payload);
    return result.data;
  }
}
