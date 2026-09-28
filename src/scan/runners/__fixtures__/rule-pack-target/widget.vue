<!-- Intentionally vulnerable corpus for the Sentinel opengrep rule pack. -->
<template>
  <!-- appsec.xss.vue-v-html -->
  <div v-html="post.body"></div>
  <!-- SAFE: interpolation escapes. -->
  <span>{{ post.title }}</span>
</template>
