import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_storage/firebase_storage.dart';
import 'refs.dart';

class ProfileRepository {
  final FirebaseFirestore _db = FirebaseFirestore.instance;

  Future<void> saveProfile(String uid, Map<String, Object?> data) =>
      _db.usersRef().doc(uid).set(data, SetOptions(merge: true));

  Future<String> uploadAvatar(String uid, List<int> bytes) async {
    final ref = FirebaseStorage.instance.ref('avatars/$uid').child('avatar.png');
    await ref.putData(Uint8List.fromList(bytes));
    return ref.getDownloadURL();
  }

  Future<void> sendFeedback(String text) =>
      _db.collection('feedback').add({'text': text, 'at': FieldValue.serverTimestamp()});
}
