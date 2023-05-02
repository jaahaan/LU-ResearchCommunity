<template>
  <div>{{ this.latestTickId }}</div>
</template>

<script>
export default {
  data() {
    return {
      latestTickId: 0,
    };
  },
  mounted() {
    const vm = this;

    // use "main" socket defined in nuxt.config.js
    vm.socket = this.$nuxtSocket({
      name: "main", // select "main" socket from nuxt.config.js - we could also skip this because "main" is the default socket
    });

    vm.socket.on("tick", (tickId) => {
      vm.latestTickId = tickId;
    });
  },
};
</script>
