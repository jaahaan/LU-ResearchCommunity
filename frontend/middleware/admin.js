export default function ({ store, redirect }) {
    // If the user is not authenticated
    if (!store.state.authUser && store.state.authUser.userType!='admin') {
      // console.log("hello ghdvyhevdg")
      return redirect('/login')
    } else if (store.state.authUser && store.state.authUser.userType!='admin') {
        // console.log("hello ghdvyhevdg")
        return redirect('/home')
      }
  }
  