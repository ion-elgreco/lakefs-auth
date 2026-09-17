{{- define "lakefs-auth.labels" -}}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: lakefs-auth
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/*
Default image refs. `.Chart.AppVersion` is overridden by the release-helm
workflow's `helm package --app-version`, so a chart packaged at v0.2.0
resolves these to `:0.2.0` without touching values.yaml.
*/}}
{{- define "lakefs-auth.authzImage" -}}
{{ .Values.authz.image | default (printf "ghcr.io/ion-elgreco/lakefs-authz:%s" .Chart.AppVersion) }}
{{- end -}}

{{- define "lakefs-auth.authnImage" -}}
{{ .Values.authn.image | default (printf "ghcr.io/ion-elgreco/lakefs-authn:%s" .Chart.AppVersion) }}
{{- end -}}

{{/* Secret that holds the shared secret: the user's Secret, or the one this chart creates. */}}
{{- define "lakefs-auth.sharedSecretName" -}}
{{- if .Values.sharedSecret.existingSecret -}}
{{ .Values.sharedSecret.existingSecret }}
{{- else if .Values.sharedSecret.value -}}
lakefs-auth-shared-secret
{{- else -}}
{{ fail "set sharedSecret.existingSecret to a Secret that holds the lakeFS auth.encrypt.secret_key, or sharedSecret.value" }}
{{- end -}}
{{- end -}}

{{- define "lakefs-auth.databaseSecretName" -}}
{{- if .Values.authz.database.existingSecret -}}
{{ .Values.authz.database.existingSecret }}
{{- else if .Values.authz.database.url -}}
lakefs-authz-database
{{- else -}}
{{ fail "set authz.database.existingSecret to a Secret that holds the PostgreSQL connection string, or authz.database.url" }}
{{- end -}}
{{- end -}}

{{/* Empty when the OIDC client is public. */}}
{{- define "lakefs-auth.oidcClientSecretName" -}}
{{- if .Values.authn.oidc.clientSecret.existingSecret -}}
{{ .Values.authn.oidc.clientSecret.existingSecret }}
{{- else if .Values.authn.oidc.clientSecret.value -}}
lakefs-authn-oidc
{{- end -}}
{{- end -}}

{{- define "lakefs-auth.authzUrl" -}}
{{- if .Values.authn.authzUrl -}}
{{ .Values.authn.authzUrl }}
{{- else -}}
http://lakefs-authz.{{ .Release.Namespace }}.svc:{{ .Values.authz.port }}{{ .Values.authz.basePath }}
{{- end -}}
{{- end -}}

{{/* The images run as the distroless nonroot user and need no writable filesystem. */}}
{{- define "lakefs-auth.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "lakefs-auth.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end -}}
