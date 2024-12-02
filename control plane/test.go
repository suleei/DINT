package main
 
import (
	"fmt"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/dalzilio/rudd"
)
func main() {
	bdd, _ := rudd.New(32)
	a := bdd.And(bdd.Ithvar(1),bdd.Ithvar(2))
	c := bdd.And(bdd.Ithvar(1), bdd.Ithvar(2))
	required:= mapset.NewSet[rudd.Node]()
	required.Add(c)
	required.Add(a)
	required.Remove(a)
	fmt.Println(a==c)
	for v := range required.Iter(){
		fmt.Println(v)
	}
}