import iView from 'iview';
import locale from 'iview/dist/locale/en-US'; // Change locale, check node_modules/iview/dist/locale
import Vue from 'vue';
import VueTyperPlugin from 'vue-typer';
import { mapGetters } from 'vuex';
 
Vue.use(VueTyperPlugin)

Vue.use(iView, {
  locale
})


// mixins for using common methods

Vue.mixin({
    computed:{
        ...mapGetters({
            departmentInfo: "getDepartment",
            themeInfo: "getTheme",

        })
    },
    
    methods: {
        i(msg, i = 'Hey!') {
            this.$Notice.info({
                title: i,
                desc: msg
            });
        },
        s(msg, i = 'Great!') {
            // this.$Message.success('This is a success tip');
            this.$Notice.success({
                title: i,
                desc: msg
            });
        },
        s_msg(msg) {
            this.$Message.success(msg);
        },
        w(msg, i = 'Hi!') {
            this.$Notice.warning({
                title: i,
                desc: msg
            });
        },
        e(msg) {
            // this.$Message.error(msg);
            this.$Notice.error({
                desc: msg,
            });
        },
        e_msg(msg) {
            this.$Message.error(msg);
            
        },
        swr() {
            // this.$Message.error('Something went wrong, please try again later');

            this.$Notice.error({
                title: 'Oops',
                desc: 'Something went wrong, please try again later'
            });
        },
        instance (type, msg) {
            const title = msg;
            // const content = '<p>Content of dialog</p><p>Content of dialog</p>';
            switch (type) {
                case 'info':
                    this.$Modal.info({
                        title: title,
                        // content: content
                    });
                    break;
                case 'success':
                    this.$Modal.success({
                        title: msg,
                        // content: content
                    });
                    break;
                case 'warning':
                    this.$Modal.warning({
                        title: title,
                        // content: content
                    });
                    break;
                case 'error':
                    this.$Modal.error({
                        title: title,
                        // content: content
                    });
                    break;
            }
        }
       
    }
})

