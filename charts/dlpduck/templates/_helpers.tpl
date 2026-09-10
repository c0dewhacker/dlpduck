{{/* Chart and resource names. */}}
{{- define "dlpduck.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dlpduck.fullname" -}}
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

{{- define "dlpduck.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dlpduck.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dlpduck.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "dlpduck.labels" -}}
helm.sh/chart: {{ include "dlpduck.chart" . }}
{{ include "dlpduck.selectorLabels" . }}
app.kubernetes.io/component: document-processor
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "dlpduck.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "dlpduck.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "dlpduck.configMapName" -}}
{{- default (printf "%s-config" (include "dlpduck.fullname" .)) .Values.configuration.existingConfigMap }}
{{- end }}

{{- define "dlpduck.secretName" -}}
{{- if .Values.secrets.create }}
{{- printf "%s-secret" (include "dlpduck.fullname" .) }}
{{- else }}
{{- required "secrets.existingSecret is required when secrets.create is false" .Values.secrets.existingSecret }}
{{- end }}
{{- end }}

{{- define "dlpduck.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{- define "dlpduck.claimName" -}}
{{- $root := index . 0 -}}
{{- $store := index . 1 -}}
{{- $settings := index $root.Values.persistence $store -}}
{{- default (printf "%s-%s" (include "dlpduck.fullname" $root) $store) $settings.existingClaim -}}
{{- end }}

