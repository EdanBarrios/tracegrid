import { supabase } from '@/lib/supabase';

export async function listProjects() {
  return supabase.from('projects').select('id, name');
}

export async function createProject(name: string) {
  return supabase.rpc('create_project', { p_name: name });
}

export async function addTask(projectId: string, title: string) {
  return supabase.from('tasks').insert({ project_id: projectId, title });
}

export async function stats(projectId: string, v2: boolean) {
  // cast and ternary: both names are recorded (inferred)
  return (supabase.rpc as any)(v2 ? 'project_stats_v2' : 'project_stats', { p: projectId });
}

export async function count(tableName: string) {
  // dynamic name: counted as unresolved, never dropped
  return supabase.from(tableName).select('*', { count: 'exact', head: true });
}

export async function uploadAvatar(file: File) {
  return supabase.storage.from('avatars').upload(`me/${file.name}`, file);
}

export function wipe() {
  // calls an RPC no migration defines
  return supabase.rpc('delete_everything');
}

export const ids = Array.from(new Set(['a', 'b']));
