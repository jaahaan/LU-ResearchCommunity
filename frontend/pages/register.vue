<template>
  <div class="login-section">
    <div class="left">
      <img :src="'/assets/images/lurc.png'" alt="img" />
    </div>

    <div class="right">
      <div class="form">
        <div class="topButton">
          <button
            class="main-btn"
            v-for="(tab, index) in tabs"
            :key="tab"
            @click="component = tab"
            :class="component === tab ? 'active' : ''"
          >
            {{ tab }}
          </button>
        </div>
        <h1>Register As {{ component }}</h1>

        <component :is="component" />
      </div>
    </div>
  </div>
</template>

<script>
import Teacher from "~/components/registerTeacher";
import Student from "~/components/registerStudent";

export default {
  middleware: "guest",

  components: {
    Teacher,
    Student,
  },
  data() {
    return {
      tabs: ["Teacher", "Student"],
      component: "Teacher",
    };
  },
};
</script>

<style scoped>
.active {
  color: #ffffff !important;
  background: #566d7e;
  border: 2px solid #566d7e;
}
</style>
