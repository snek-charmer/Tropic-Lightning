{{/*
Expand the name of the chart.
*/}}
{{- define "keycloak-portal.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "keycloak-portal.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "keycloak-portal.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "keycloak-portal.labels" -}}
helm.sh/chart: {{ include "keycloak-portal.chart" . }}
{{ include "keycloak-portal.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "keycloak-portal.selectorLabels" -}}
app.kubernetes.io/name: {{ include "keycloak-portal.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "keycloak-portal.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "keycloak-portal.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Full external host under UDS: explicit fullHost if set, else <host>.<domain>.
expose.host is only the subdomain (UDS appends the domain), so redirect URLs must
use this full host, not expose.host alone.
*/}}
{{- define "keycloak-portal.udsFullHost" -}}
{{- if .Values.uds.expose.fullHost -}}
{{- .Values.uds.expose.fullHost -}}
{{- else -}}
{{- printf "%s.%s" .Values.uds.expose.host .Values.uds.expose.domain -}}
{{- end -}}
{{- end }}

{{/*
OIDC issuer under UDS: explicit uds.sso.issuer if set, else derived from the
Keycloak subdomain + cluster domain + realm. Deriving avoids a crash when the
issuer isn't passed at deploy time (the standard UDS issuer is
https://sso.<domain>/realms/uds).
*/}}
{{- define "keycloak-portal.udsIssuer" -}}
{{- if .Values.uds.sso.issuer -}}
{{- .Values.uds.sso.issuer -}}
{{- else -}}
{{- printf "https://%s.%s/realms/%s" .Values.uds.sso.keycloakHost .Values.uds.expose.domain .Values.uds.sso.realm -}}
{{- end -}}
{{- end }}

{{/*
Name of the Secret holding the OIDC client secret. With UDS, the UDS Operator
generates it (uds.sso.secretName). Otherwise an existing or chart-created Secret.
*/}}
{{- define "keycloak-portal.secretName" -}}
{{- if .Values.uds.enabled }}
{{- .Values.uds.sso.secretName }}
{{- else if .Values.clientSecret.existingSecret.name }}
{{- .Values.clientSecret.existingSecret.name }}
{{- else }}
{{- include "keycloak-portal.fullname" . }}
{{- end }}
{{- end }}

{{/*
Key within the Secret that holds the OIDC client secret.
*/}}
{{- define "keycloak-portal.secretKey" -}}
{{- if .Values.uds.enabled }}
{{- "OIDC_CLIENT_SECRET" }}
{{- else if .Values.clientSecret.existingSecret.name }}
{{- default "OIDC_CLIENT_SECRET" .Values.clientSecret.existingSecret.key }}
{{- else }}
{{- "OIDC_CLIENT_SECRET" }}
{{- end }}
{{- end }}
