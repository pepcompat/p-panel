export interface Meta {
  requestId: string;
}
export interface Paginate {
  page: number;
  limit: number;
  total: number;
}
export interface SuccessEnvelope<T> {
  success: true;
  statusCode: 0;
  message: string;
  data: T;
  meta: Meta;
}
export interface ListEnvelope<T> extends SuccessEnvelope<T[]> {
  paginate: Paginate;
}
export interface ErrorEnvelope {
  error: { code: string; message: string; details?: unknown };
  meta?: Meta;
}
